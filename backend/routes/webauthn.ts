/// <reference path="../types/express-session-augment.d.ts" />
import { Router, type Request, type Response } from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticatorTransportFuture,
} from '@simplewebauthn/server';
import { User } from '../models/User';
import { Credential } from '../models/Credential';
import { Challenge } from '../models/Challenge';
import { logger } from '../utils/logger';

const router = Router();

const RP_ID          = process.env.RP_ID          ?? '';
const ORIGIN         = process.env.ORIGIN         ?? '';
const ANDROID_ORIGIN = process.env.ANDROID_ORIGIN ?? '';
const RP_NAME        = process.env.RP_NAME        ?? 'DLA Research Prototype';

// Accept web origin + Android apk-key-hash origin (if configured)
const EXPECTED_ORIGINS = [ORIGIN, ANDROID_ORIGIN].filter(Boolean);

function summarizeValue(value: string | undefined): string {
  if (!value) return 'missing';
  if (value.length <= 12) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

// ── Registration: generate options ───────────────────────────────────────────
router.post('/register/options', async (req: Request, res: Response) => {
  try {
    const { email, displayName } = req.body as { email?: string; displayName?: string };
    if (!email) {
      res.status(400).json({ error: 'email is required' });
      return;
    }
    const resolvedName = displayName ?? email.split('@')[0] ?? email;

    // Upsert user
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, displayName: resolvedName });
    }
    const uid = (user._id as object).toString();

    // Exclude already-registered credentials
    const existing = await Credential.find({ userId: uid });
    const options = await generateRegistrationOptions({
      rpName:    RP_NAME,
      rpID:      RP_ID,
      userID:    Buffer.from(uid),
      userName:  email,
      userDisplayName: resolvedName,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: existing.map(c => ({
        id: c.credentialId,
        ...(c.transports ? { transports: c.transports } : {}),
      })),
    });

    await Challenge.deleteMany({ userId: uid, type: 'registration' });
    await Challenge.create({
      userId:    uid,
      type:      'registration',
      challenge: options.challenge,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    res.json({ userId: uid, options });
  } catch (err) {
    console.error('[webauthn] register/options error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ── Registration: verify response ────────────────────────────────────────────
router.post('/register/verify', async (req: Request, res: Response) => {
  try {
    const { userId, response } = req.body as { userId?: string; response?: unknown };
    if (!userId || !response) {
      res.status(400).json({ error: 'userId and response are required' });
      return;
    }

    const ch = await Challenge.findOne({ userId, type: 'registration' });
    if (!ch) {
      res.status(400).json({ error: 'challenge not found or expired' });
      return;
    }

    const verification = await verifyRegistrationResponse({
      response:          response as Parameters<typeof verifyRegistrationResponse>[0]['response'],
      expectedChallenge: ch.challenge,
      expectedOrigin:    EXPECTED_ORIGINS,
      expectedRPID:      RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      res.status(400).json({ error: 'verification failed' });
      return;
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const respBody = response as { response?: { transports?: AuthenticatorTransportFuture[] } };

    await Credential.create({
      userId:       userId,
      credentialId: credential.id,
      publicKey:    Buffer.from(credential.publicKey),
      signCount:    credential.counter,
      deviceType:   credentialDeviceType,
      backedUp:     credentialBackedUp,
      transports:   respBody.response?.transports ?? [],
    });

    await Challenge.deleteMany({ userId, type: 'registration' });

    // Layer 1 complete — hand off to Layer 2 (device verification)
    const user = await User.findById(userId);
    const username = user?.displayName ?? user?.email ?? userId;
    req.session.passkeyVerified = { userId, username, verifiedAt: Date.now() };

    res.json({ verified: true, username, nextStep: 'DEVICE_VERIFICATION' });
  } catch (err) {
    console.error('[webauthn] register/verify error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ── Authentication: generate options ─────────────────────────────────────────
router.post('/authenticate/options', async (req: Request, res: Response) => {
  try {
    const { userId, email } = req.body as { userId?: string; email?: string };

    let resolvedUserId = userId;
    if (!resolvedUserId && email) {
      const user = await User.findOne({ email });
      if (!user) {
        res.status(404).json({ error: 'no account found for this email' });
        return;
      }
      resolvedUserId = (user._id as object).toString();
    }

    if (!resolvedUserId) {
      console.warn('[webauthn] authenticate/options rejected: missing userId/email', {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      res.status(400).json({ error: 'userId or email is required' });
      return;
    }

    const userCreds = await Credential.find({ userId: resolvedUserId });
    if (!userCreds.length) {
      console.warn('[webauthn] authenticate/options rejected: no credentials', {
        userId: resolvedUserId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      res.status(404).json({ error: 'no credentials found for user' });
      return;
    }

    const useAllowCredentials = req.body.useAllowCredentials === true;
    const allowCredentials = userCreds.map(c => ({
      id: c.credentialId,
      ...(c.transports ? { transports: c.transports } : {}),
    }));

    const generatedOptions = await generateAuthenticationOptions({
      rpID: RP_ID,
      ...(useAllowCredentials ? { allowCredentials } : {}),
      userVerification: 'preferred',
    });
    const options = {
      ...generatedOptions,
      // Empty allowCredentials lets Android/Google Password Manager discover
      // resident passkeys for this RP instead of filtering by a stale/misencoded ID.
      allowCredentials: useAllowCredentials ? generatedOptions.allowCredentials : [],
    };

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const deleted = await Challenge.deleteMany({ userId: resolvedUserId, type: 'authentication' });
    await Challenge.create({
      userId:    resolvedUserId,
      type:      'authentication',
      challenge: options.challenge,
      expiresAt,
    });

    console.log('[webauthn] authenticate/options issued', {
      userId: resolvedUserId,
      rpId: RP_ID,
      credentialCount: userCreds.length,
      credentialIds: userCreds.map(c => summarizeValue(c.credentialId)),
      discoverable: !useAllowCredentials,
      challenge: summarizeValue(options.challenge),
      expiresAt: expiresAt.toISOString(),
      replacedChallenges: deleted.deletedCount,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({ userId: resolvedUserId, options });
  } catch (err) {
    console.error('[webauthn] authenticate/options error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ── Authentication: verify response ──────────────────────────────────────────
router.post('/authenticate/verify', async (req: Request, res: Response) => {
  try {
    const { userId, response } = req.body as { userId?: string; response?: { id?: string } };
    if (!userId || !response) {
      res.status(400).json({ error: 'userId and response are required' });
      return;
    }

    const credentialId = response.id;
    if (!credentialId) {
      res.status(400).json({ error: 'response.id is required' });
      return;
    }

    const ch = await Challenge.findOne({ userId, type: 'authentication' }).sort({ _id: -1 });
    if (!ch) {
      console.warn('[webauthn] authenticate/verify rejected: challenge not found', {
        userId,
        credentialId: summarizeValue(credentialId),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      res.status(400).json({ error: 'challenge not found or expired' });
      return;
    }

    const cred = await Credential.findOne({ credentialId, userId });
    if (!cred) {
      console.warn('[webauthn] authenticate/verify rejected: credential not found', {
        userId,
        credentialId: summarizeValue(credentialId),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      res.status(404).json({ error: 'credential not found' });
      return;
    }

    console.log('[webauthn] authenticate/verify received', {
      userId,
      credentialId: summarizeValue(credentialId),
      expectedChallenge: summarizeValue(ch.challenge),
      challengeExpiresAt: ch.expiresAt.toISOString(),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    const verification = await verifyAuthenticationResponse({
      response:          response as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
      expectedChallenge: ch.challenge,
      expectedOrigin:    EXPECTED_ORIGINS,
      expectedRPID:      RP_ID,
      credential: {
        id:        cred.credentialId,
        publicKey: new Uint8Array(cred.publicKey),
        counter:   cred.signCount,
        ...(cred.transports ? { transports: cred.transports } : {}),
      },
    });

    if (!verification.verified) {
      console.warn('[webauthn] authenticate/verify failed', {
        userId,
        credentialId: summarizeValue(credentialId),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      await logger.audit({
        event:    'PASSKEY_AUTH_FAILED',
        severity: 'WARNING',
        userId,
        ip:       req.ip,
        userAgent: req.headers['user-agent'],
        message:  'Passkey authentication verification failed',
      });
      res.status(400).json({ error: 'verification failed' });
      return;
    }

    await Credential.updateOne(
      { _id: cred._id },
      { $set: { signCount: verification.authenticationInfo.newCounter } },
    );
    await Challenge.deleteMany({ userId, type: 'authentication' });

    // Layer 1 complete — hand off to Layer 2 (device verification)
    const user = await User.findById(userId);
    const username = user?.displayName ?? user?.email ?? userId;
    req.session.passkeyVerified = { userId, username, verifiedAt: Date.now() };

    await logger.audit({
      event:     'PASSKEY_AUTH_SUCCESS',
      severity:  'INFO',
      userId,
      username,
      ip:        req.ip,
      userAgent: req.headers['user-agent'],
      message:   'Passkey authentication successful — proceeding to device verification',
    });

    console.log('[webauthn] authenticate/verify succeeded', {
      userId,
      username,
      credentialId: summarizeValue(credentialId),
      newCounter: verification.authenticationInfo.newCounter,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({ verified: true, username, nextStep: 'DEVICE_VERIFICATION' });
  } catch (err) {
    console.error('[webauthn] authenticate/verify error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

export default router;
