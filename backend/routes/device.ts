/// <reference path="../types/express-session-augment.d.ts" />
import { Router, type Request, type Response, type NextFunction } from 'express';
import { randomUUID } from 'crypto';
import mongoose from 'mongoose';
import { DeviceProfile } from '../models/DeviceProfile';
import { ApprovalRequest } from '../models/ApprovalRequest';
import { computeDeviceId, generateDbkChallenge, verifyDbkSignature, verifyDbkSignatureOverMessage } from '../utils/crypto';
import { logger } from '../utils/logger';

const router = Router();

// ── Types ─────────────────────────────────────────────────────────────────────

interface Signals {
  userAgent?: string;
  platform?:  string;
  timezone?:  string;
}

interface ClientMetrics {
  dbkGenMs?:  number;
  dbkSignMs?: number;
  totalMs?:   number;
}

// ── Middleware: requirePasskeyVerified ────────────────────────────────────────

function requirePasskeyVerified(req: Request, res: Response, next: NextFunction): void {
  const pv = req.session.passkeyVerified;
  if (!pv) {
    res.status(401).json({ error: 'Passkey verification required' });
    return;
  }
  if (Date.now() - pv.verifiedAt > 5 * 60 * 1000) {
    delete req.session.passkeyVerified;
    res.status(401).json({ error: 'Passkey session expired — re-authenticate' });
    return;
  }
  next();
}

// ── Middleware: requireAuthenticated ──────────────────────────────────────────

function requireAuthenticated(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.authenticated) {
    res.status(401).json({ error: 'Full authentication required' });
    return;
  }
  next();
}

// ── Helper: collect signals from request ─────────────────────────────────────

function collectSignals(req: Request, body: Signals) {
  return {
    userAgent: body.userAgent ?? req.headers['user-agent'] ?? '',
    platform:  body.platform  ?? '',
    timezone:  body.timezone  ?? '',
    ip:        (req.ip ?? req.socket.remoteAddress ?? ''),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. POST /api/device/challenge
// ─────────────────────────────────────────────────────────────────────────────
router.post('/challenge', requirePasskeyVerified, async (req: Request, res: Response) => {
  try {
    const challengeTimer = logger.startTimer();

    const { dbkPublicKey } = req.body as { dbkPublicKey?: object };
    if (!dbkPublicKey || typeof dbkPublicKey !== 'object') {
      res.status(400).json({ error: 'dbkPublicKey is required' });
      return;
    }

    const userId         = req.session.passkeyVerified!.userId;
    const userObjId      = new mongoose.Types.ObjectId(userId);
    const deviceId       = computeDeviceId(dbkPublicKey);
    const trustedDeviceCount = await DeviceProfile.countDocuments({ userId: userObjId, status: 'TRUSTED' });

    const challenge      = generateDbkChallenge();
    const loginAttemptId = randomUUID();
    const now            = Date.now();
    const challengeMs    = challengeTimer.elapsed();

    if (req.session.dbkChallenge) {
      console.log(`[DBK-CHALLENGE] Replacing unused challenge for userId=${userId} loginAttemptId=${req.session.dbkChallenge.loginAttemptId}`);
    }

    req.session.dbkChallenge = {
      challenge,
      userId,
      expectedDeviceId:   deviceId,
      expectedPubKey:     dbkPublicKey,
      loginAttemptId,
      createdAt:          now,
      expiresAt:          now + 120_000,
      trustedDeviceCount,
    };

    console.log(`[DBK-CHALLENGE] === Challenge issued ===`);
    console.log(`[DBK-CHALLENGE] LoginAttemptId: ${loginAttemptId}`);
    console.log(`[DBK-CHALLENGE] ExpectedDeviceId: ${deviceId}`);
    console.log(`[DBK-CHALLENGE] TrustedDevices: ${trustedDeviceCount}`);
    console.log(`[DBK-CHALLENGE] ExpiresIn: 120s`);

    res.json({
      challenge,
      trustedDeviceCount,
      isBootstrap: trustedDeviceCount === 0,
      _meta: { challengeMs },
    });
  } catch (err) {
    console.error('[device] challenge error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. POST /api/device/verify
// ─────────────────────────────────────────────────────────────────────────────
router.post('/verify', requirePasskeyVerified, async (req: Request, res: Response) => {
  const totalTimer = logger.startTimer();

  try {
    // ── Consume challenge FIRST (prevents replay) ─────────────────────────
    const challengeData = req.session.dbkChallenge;
    delete req.session.dbkChallenge;
    console.log(`[DBK-VERIFY] Challenge consumed`);

    if (!challengeData) {
      res.status(400).json({ error: 'No pending DBK challenge — call /challenge first' });
      return;
    }
    if (challengeData.userId !== req.session.passkeyVerified!.userId) {
      res.status(403).json({ error: 'Challenge user mismatch' });
      return;
    }
    if (Date.now() > challengeData.expiresAt) {
      await logger.audit({
        event:    'DBK_CHALLENGE_EXPIRED',
        severity: 'WARNING',
        userId:   challengeData.userId,
        message:  'DBK challenge expired before use',
        ip:       req.ip,
      });
      res.status(400).json({ error: 'DBK challenge expired' });
      return;
    }

    const { signature, signals, clientMetrics } =
      req.body as {
        signature?:     string;
        signals?:       Signals;
        clientMetrics?: ClientMetrics;
      };

    if (!signature) {
      res.status(400).json({ error: 'signature is required' });
      return;
    }

    const userId   = challengeData.userId;
    const username = req.session.passkeyVerified!.username;
    const ip       = req.ip ?? '';
    const ua       = req.headers['user-agent'];

    // ── Device lookup (deviceId already computed at /challenge time) ────────
    const lookupTimer    = logger.startTimer();
    const deviceId       = challengeData.expectedDeviceId;
    const userObjId      = new mongoose.Types.ObjectId(userId);
    const collected      = collectSignals(req, signals ?? {});
    const trustedCount   = challengeData.trustedDeviceCount;
    const existing       = await DeviceProfile.findOne({ userId: userObjId, deviceId });
    const deviceLookupMs = lookupTimer.elapsed();

    // ── Select verification key (fully server-authoritative) ─────────────
    // Existing devices: use stored key — client cannot influence which key is used.
    // First enrollment: use key submitted at /challenge time (session.expectedPubKey),
    //   never from the /verify request body.
    const keyToVerify: object = existing
      ? JSON.parse(existing.dbkPublicKey) as object
      : challengeData.expectedPubKey;

    // ── [DBK-VERIFY] Detailed cryptographic log ───────────────────────────
    const jwk        = keyToVerify as Record<string, unknown>;
    const challengeB = Buffer.from(challengeData.challenge, 'base64url');
    const sigB       = Buffer.from(signature, 'base64url');
    const xVal       = typeof jwk['x'] === 'string' ? jwk['x'] : '';
    const yVal       = typeof jwk['y'] === 'string' ? jwk['y'] : '';
    const xBytes     = Buffer.from(xVal, 'base64url');
    const yBytes     = Buffer.from(yVal, 'base64url');
    const isIeeeP1363 = sigB.length === 64;
    const keySource   = existing ? 'STORED' : 'CLIENT-SUPPLIED (enrollment)';

    console.log(`[DBK-VERIFY] === Device verification started ===`);
    console.log(`[DBK-VERIFY] LoginAttemptId: ${challengeData.loginAttemptId}`);
    console.log(`[DBK-VERIFY] User: ${username}`);
    console.log(`[DBK-VERIFY] Challenge: ${challengeData.challenge.slice(0, 16)}... (${challengeB.length} bytes)`);
    console.log(`[DBK-VERIFY] Key source: ${keySource}`);
    console.log(`[DBK-VERIFY] Public key (x): ${xVal.slice(0, 16)}... (${xBytes.length} bytes)`);
    console.log(`[DBK-VERIFY] Public key (y): ${yVal.slice(0, 16)}... (${yBytes.length} bytes)`);
    console.log(`[DBK-VERIFY] Signature: ${signature.slice(0, 16)}... (${sigB.length} bytes ${isIeeeP1363 ? 'IEEE P-1363' : 'unexpected format'})`);

    // ── Verify DBK signature (timed) ──────────────────────────────────────
    const sigTimer    = logger.startTimer();
    const sigValid    = verifyDbkSignature(keyToVerify, challengeData.challenge, signature);
    const dbkVerifyMs = sigTimer.elapsed();

    console.log(`[DBK-VERIFY] Signature valid: ${sigValid ? 'TRUE' : 'FALSE'}`);
    console.log(`[DBK-VERIFY] DeviceId: ${deviceId}`);
    if (existing) {
      console.log(`[DBK-VERIFY] DeviceProfile lookup: FOUND, status=${existing.status}`);
    } else {
      console.log(`[DBK-VERIFY] DeviceProfile lookup: NOT FOUND (trustedCount=${trustedCount})`);
    }

    const flow = trustedCount === 0 && !existing                                      ? 'BOOTSTRAP'
               : existing?.status === 'TRUSTED'                                       ? 'TRUSTED_DEVICE'
               : !existing && trustedCount >= 1                                       ? 'NEW_DEVICE'
               : existing?.status === 'PENDING'                                       ? 'PENDING'
               : existing?.status === 'REJECTED' || existing?.status === 'REVOKED'   ? 'BLOCKED'
               : 'UNKNOWN';
    console.log(`[DBK-VERIFY] Decision: ${flow} flow`);
    console.log(`[DBK-VERIFY] === Device verification complete ===`);

    if (!sigValid) {
      await logger.dbkSignatureInvalid({ userId, username, ip });
      await logger.authAttempt({
        userId, username, ip, userAgent: ua,
        flow:    'FAILED',
        outcome: 'FAILED_DBK',
        latency: { dbkVerifyMs, deviceLookupMs, totalMs: totalTimer.elapsed() },
        errorMessage: 'DBK signature verification failed',
        errorStep:    'DBK_VERIFY',
      });
      res.status(403).json({ error: 'Invalid DBK signature' });
      return;
    }

    const clientDbkGenMs  = clientMetrics?.dbkGenMs;
    const clientDbkSignMs = clientMetrics?.dbkSignMs;
    const clientTotalMs   = clientMetrics?.totalMs;

    const baseLatency = { dbkVerifyMs, deviceLookupMs, clientDbkGenMs, clientDbkSignMs, clientTotalMs };

    // ── BOOTSTRAP ─────────────────────────────────────────────────────────
    if (trustedCount === 0 && !existing) {
      // Atomic upsert via compound unique index (userId, deviceId).
      // Two concurrent requests with *different* deviceIds can both land here,
      // so we re-check the trusted count after insert to detect that race.
      await DeviceProfile.collection.findOneAndUpdate(
        { userId: userObjId, deviceId },
        {
          $setOnInsert: {
            userId:       userObjId,
            deviceId,
            dbkPublicKey: JSON.stringify(challengeData.expectedPubKey),
            status:       'TRUSTED',
            enrollmentSignals: { ...collected, enrolledAt: new Date() },
            createdAt:    new Date(),
            updatedAt:    new Date(),
          },
        },
        { upsert: true, returnDocument: 'after' },
      );

      const trustedCountAfter = await DeviceProfile.countDocuments({ userId: userObjId, status: 'TRUSTED' });

      if (trustedCountAfter > 1) {
        // Lost the race — demote to PENDING and request approval from the winner.
        await DeviceProfile.updateOne(
          { userId: userObjId, deviceId },
          { $set: { status: 'PENDING', updatedAt: new Date() } },
        );

        const approver = await DeviceProfile.findOne({ userId: userObjId, status: 'TRUSTED' });
        let raceApprovalId: string | undefined;
        if (approver) {
          const raceApproval = await ApprovalRequest.create({
            userId:             userObjId,
            requestingDeviceId: deviceId,
            approverDeviceId:   approver.deviceId,
            loginAttemptId:     challengeData.loginAttemptId,
            requestContext:     { ...collected, requestedAt: new Date() },
            expiresAt:          new Date(Date.now() + 5 * 60 * 1000),
          });
          raceApprovalId = (raceApproval._id as object).toString();
        }

        console.log(`[DBK-VERIFY] Bootstrap race detected — demoted ${deviceId} to PENDING`);
        await logger.audit({ event: 'BOOTSTRAP_RACE_DETECTED', severity: 'WARNING', userId, username, deviceId, ip, userAgent: ua, message: 'Concurrent bootstrap attempt — demoted to PENDING', mitigated: true });
        await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'NEW_DEVICE', outcome: 'PENDING_APPROVAL', latency: { ...baseLatency, deviceTotalMs: totalTimer.elapsed(), totalMs: totalTimer.elapsed() } });

        res.json({ flow: 'NEW_DEVICE', status: 'PENDING', deviceId, authComplete: false, approvalRequired: true, requestId: raceApprovalId, loginAttemptId: challengeData.loginAttemptId });
        return;
      }

      req.session.authenticated = { userId, username, deviceId, deviceStatus: 'TRUSTED', authenticatedAt: Date.now() };
      delete req.session.passkeyVerified;

      const deviceTotalMs = totalTimer.elapsed();
      await logger.audit({ event: 'DEVICE_ENROLLED_BOOTSTRAP', severity: 'INFO', userId, username, deviceId, ip, userAgent: ua, message: 'First device enrolled as TRUSTED' });
      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'BOOTSTRAP', outcome: 'SUCCESS', latency: { ...baseLatency, deviceTotalMs, totalMs: deviceTotalMs } });

      res.json({ flow: 'BOOTSTRAP', status: 'TRUSTED', deviceId, message: 'First device enrolled and trusted.', authComplete: true });
      return;
    }

    // ── TRUSTED DEVICE ────────────────────────────────────────────────────
    if (existing && existing.status === 'TRUSTED') {
      await DeviceProfile.updateOne(
        { _id: existing._id },
        { $set: { lastAuthSignals: { ...collected, loginAt: new Date() } } },
      );

      req.session.authenticated = { userId, username, deviceId, deviceStatus: 'TRUSTED', authenticatedAt: Date.now() };
      delete req.session.passkeyVerified;

      const deviceTotalMs = totalTimer.elapsed();
      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'TRUSTED_DEVICE', outcome: 'SUCCESS', latency: { ...baseLatency, deviceTotalMs, totalMs: deviceTotalMs } });

      res.json({ flow: 'TRUSTED_DEVICE', status: 'TRUSTED', deviceId, authComplete: true });
      return;
    }

    // ── NEW DEVICE ────────────────────────────────────────────────────────
    if (!existing && trustedCount >= 1) {
      await DeviceProfile.create({
        deviceId,
        userId:       userObjId,
        dbkPublicKey: JSON.stringify(challengeData.expectedPubKey),
        status:       'PENDING',
        enrollmentSignals: { ...collected, enrolledAt: new Date() },
      });

      const approver = await DeviceProfile.findOne({ userId: userObjId, status: 'TRUSTED' });
      let approvalRequestId: string | undefined;
      if (approver) {
        const approvalRequest = await ApprovalRequest.create({
          userId:             userObjId,
          requestingDeviceId: deviceId,
          approverDeviceId:   approver.deviceId,
          loginAttemptId:     challengeData.loginAttemptId,
          requestContext:     { ...collected, requestedAt: new Date() },
          expiresAt:          new Date(Date.now() + 5 * 60 * 1000),
        });
        approvalRequestId = (approvalRequest._id as object).toString();
        await logger.audit({ event: 'APPROVAL_REQUESTED', severity: 'INFO', userId, username, deviceId, ip, userAgent: ua, message: `Approval requested from device ${approver.deviceId}`, details: { approverDeviceId: approver.deviceId } });
      }

      await logger.audit({ event: 'DEVICE_ENROLLED_PENDING', severity: 'INFO', userId, username, deviceId, ip, userAgent: ua, message: 'New device enrolled, awaiting approval' });
      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'NEW_DEVICE', outcome: 'PENDING_APPROVAL', latency: { ...baseLatency, deviceTotalMs: totalTimer.elapsed(), totalMs: totalTimer.elapsed() } });

      res.json({ flow: 'NEW_DEVICE', status: 'PENDING', deviceId, authComplete: false, approvalRequired: true, requestId: approvalRequestId, loginAttemptId: challengeData.loginAttemptId });
      return;
    }

    // ── PENDING (poll) ────────────────────────────────────────────────────
    // DeviceProfile stays PENDING until /finalize proves fresh ownership.
    // Return approvalGranted=true + requestId when approval is ready so the
    // client knows it can proceed to /challenge → /finalize.
    if (existing && existing.status === 'PENDING') {
      const approval = await ApprovalRequest.findOne({
        requestingDeviceId: deviceId,
        userId:             userObjId,
        status:             'APPROVED',
        expiresAt:          { $gt: new Date() },
      });

      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'NEW_DEVICE', outcome: 'PENDING_APPROVAL', latency: { ...baseLatency, totalMs: totalTimer.elapsed() } });

      if (approval) {
        res.json({ flow: 'NEW_DEVICE', status: 'PENDING', deviceId, authComplete: false, approvalGranted: true, requestId: (approval._id as object).toString(), loginAttemptId: approval.loginAttemptId });
      } else {
        res.json({ flow: 'NEW_DEVICE', status: 'PENDING', deviceId, authComplete: false });
      }
      return;
    }

    // ── BLOCKED ───────────────────────────────────────────────────────────
    if (existing && (existing.status === 'REJECTED' || existing.status === 'REVOKED')) {
      await logger.deviceBlocked({ userId, username, deviceId, ip, reason: existing.status });
      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'BLOCKED', outcome: 'BLOCKED', latency: { ...baseLatency, totalMs: totalTimer.elapsed() } });
      res.status(403).json({ flow: 'BLOCKED', status: existing.status, deviceId, authComplete: false });
      return;
    }

    res.status(400).json({ error: 'Unexpected device state' });
  } catch (err) {
    console.error('[device] verify error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. GET /api/device/status/:requestId
// ─────────────────────────────────────────────────────────────────────────────
router.get('/status/:requestId', requirePasskeyVerified, async (req: Request, res: Response) => {
  try {
    const { requestId } = req.params as { requestId: string };
    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      res.status(400).json({ error: 'Invalid requestId' });
      return;
    }

    const userId    = req.session.passkeyVerified!.userId;
    const userObjId = new mongoose.Types.ObjectId(userId);

    const approval = await ApprovalRequest.findOne({
      _id:    new mongoose.Types.ObjectId(requestId),
      userId: userObjId,
    });

    if (!approval) {
      res.status(404).json({ error: 'Approval request not found' });
      return;
    }

    if (approval.status === 'PENDING' && Date.now() > approval.expiresAt.getTime()) {
      approval.status = 'EXPIRED';
      await approval.save();
    }

    const profile = await DeviceProfile.findOne({
      userId:   userObjId,
      deviceId: approval.requestingDeviceId,
    });

    res.json({
      requestId,
      deviceId:       approval.requestingDeviceId,
      approvalStatus: approval.status,
      deviceStatus:   profile?.status ?? 'NOT_FOUND',
      expiresAt:      approval.expiresAt,
    });
  } catch (err) {
    console.error('[device] status error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. GET /api/device/list
// ─────────────────────────────────────────────────────────────────────────────
router.get('/list', requireAuthenticated, async (req: Request, res: Response) => {
  try {
    const userId  = req.session.authenticated!.userId;
    const devices = await DeviceProfile.find(
      { userId: new mongoose.Types.ObjectId(userId) },
      { dbkPublicKey: 0 },
    ).lean();

    res.json({
      devices: devices.map(d => ({
        deviceId:          d.deviceId,
        status:            d.status,
        enrollmentSignals: d.enrollmentSignals,
        lastAuthSignals:   d.lastAuthSignals ?? null,
        approvedBy:        d.approvedBy ?? null,
        createdAt:         d.createdAt,
      })),
    });
  } catch (err) {
    console.error('[device] list error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. GET /api/device/approval/pending
// ─────────────────────────────────────────────────────────────────────────────
router.get('/approval/pending', requireAuthenticated, async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.session.authenticated!;

    const pending = await ApprovalRequest.find({
      approverDeviceId: deviceId,
      status:           'PENDING',
      expiresAt:        { $gt: new Date() },
    }).lean();

    res.json({
      pending: pending.map(r => ({
        requestId:          (r._id as object).toString(),
        requestingDeviceId: r.requestingDeviceId,
        approverDeviceId:   r.approverDeviceId,
        loginAttemptId:     r.loginAttemptId,
        approvalNonce:      r.approvalNonce,
        requestContext:     r.requestContext,
        expiresAt:          r.expiresAt,
        createdAt:          r.createdAt,
      })),
    });
  } catch (err) {
    console.error('[device] approval/pending error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. POST /api/device/approval/decide
// ─────────────────────────────────────────────────────────────────────────────
router.post('/approval/decide', requireAuthenticated, async (req: Request, res: Response) => {
  try {
    const auth = req.session.authenticated!;
    if (auth.deviceStatus !== 'TRUSTED') {
      res.status(403).json({ error: 'Only trusted devices can approve or deny requests' });
      return;
    }

    const { requestId, decision, signature } =
      req.body as { requestId?: string; decision?: 'APPROVED' | 'DENIED'; signature?: string };

    if (!requestId || !decision || !['APPROVED', 'DENIED'].includes(decision)) {
      res.status(400).json({ error: 'requestId and decision (APPROVED|DENIED) are required' });
      return;
    }
    if (!signature) {
      res.status(400).json({ error: 'signature is required' });
      return;
    }

    const approval = await ApprovalRequest.findById(requestId);
    if (!approval) {
      res.status(404).json({ error: 'Approval request not found' });
      return;
    }
    if (approval.approverDeviceId !== auth.deviceId) {
      res.status(403).json({ error: 'This approval request is not assigned to your device' });
      return;
    }
    if (approval.status !== 'PENDING') {
      res.status(409).json({ error: `Request is already ${approval.status}` });
      return;
    }
    if (approval.expiresAt < new Date()) {
      res.status(410).json({ error: 'Approval request has expired' });
      return;
    }

    // Verify approver's DBK signature over canonical payload
    const payload = [
      'DLA-APPROVAL', 'v1',
      requestId,
      approval.requestingDeviceId,
      approval.approverDeviceId,
      approval.loginAttemptId,
      decision,
      approval.approvalNonce,
    ].join('|');

    const approverProfile = await DeviceProfile.findOne({ userId: approval.userId, deviceId: auth.deviceId, status: 'TRUSTED' });
    if (!approverProfile) {
      res.status(403).json({ error: 'Approver device profile not found' });
      return;
    }
    const approverKey = JSON.parse(approverProfile.dbkPublicKey) as object;
    const sigValid    = verifyDbkSignatureOverMessage(approverKey, payload, signature);

    if (!sigValid) {
      await logger.audit({
        event:        'APPROVAL_SIGNATURE_INVALID',
        severity:     'CRITICAL',
        userId:       auth.userId,
        username:     auth.username,
        deviceId:     auth.deviceId,
        ip:           req.ip,
        userAgent:    req.headers['user-agent'],
        message:      'DBK signature verification failed on approval/decide — possible forged approval',
        attackVector: 'forged_approval',
        mitigated:    true,
      });
      res.status(403).json({ error: 'Invalid DBK signature' });
      return;
    }

    approval.status           = decision;
    approval.resolvedAt       = new Date();
    approval.approvalSignature = signature;
    approval.decisionPayload  = payload;
    await approval.save();

    const userObjId  = approval.userId;
    const userId     = userObjId.toString();
    const { username } = auth;

    if (decision === 'APPROVED') {
      // DeviceProfile stays PENDING — promotion to TRUSTED happens in /finalize
      // only after the requesting device proves fresh ownership with a signature.
      await logger.deviceApproved({ userId, username, deviceId: approval.requestingDeviceId, approverDeviceId: auth.deviceId });
    } else {
      await DeviceProfile.updateOne(
        { userId: userObjId, deviceId: approval.requestingDeviceId },
        { $set: { status: 'REJECTED' } },
      );
      await logger.deviceDenied({ userId, username, deviceId: approval.requestingDeviceId, approverDeviceId: auth.deviceId });
    }

    res.json({
      decision,
      requestingDeviceId: approval.requestingDeviceId,
      message: decision === 'APPROVED'
        ? 'Device approved — awaiting finalization by requesting device.'
        : 'Device denied and marked REJECTED.',
    });
  } catch (err) {
    console.error('[device] approval/decide error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. POST /api/device/finalize
// Completes new-device enrollment after approval:
//   /challenge → /finalize (with requestId + loginAttemptId + signature)
// Only after a valid fresh signature does the DeviceProfile become TRUSTED.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/finalize', requirePasskeyVerified, async (req: Request, res: Response) => {
  const totalTimer = logger.startTimer();

  try {
    // Consume challenge FIRST (prevents replay — must be fresh challenge_2,
    // separate from challenge_1 consumed by /verify)
    const challengeData = req.session.dbkChallenge;
    delete req.session.dbkChallenge;
    console.log(`[DBK-FINALIZE] Challenge consumed`);

    if (!challengeData) {
      res.status(400).json({ error: 'No pending DBK challenge — call /challenge first' });
      return;
    }
    if (challengeData.userId !== req.session.passkeyVerified!.userId) {
      res.status(403).json({ error: 'Challenge user mismatch' });
      return;
    }
    if (Date.now() > challengeData.expiresAt) {
      res.status(400).json({ error: 'DBK challenge expired' });
      return;
    }

    const { requestId, loginAttemptId, signature } =
      req.body as { requestId?: string; loginAttemptId?: string; signature?: string };

    if (!requestId || !loginAttemptId || !signature) {
      res.status(400).json({ error: 'requestId, loginAttemptId, and signature are required' });
      return;
    }

    const userId    = challengeData.userId;
    const username  = req.session.passkeyVerified!.username;
    const ip        = req.ip ?? '';
    const ua        = req.headers['user-agent'];
    const userObjId = new mongoose.Types.ObjectId(userId);
    const deviceId  = challengeData.expectedDeviceId;

    // Validate ApprovalRequest — must be APPROVED and bound to this loginAttemptId
    const approval = await ApprovalRequest.findOne({
      _id:            new mongoose.Types.ObjectId(requestId),
      userId:         userObjId,
      loginAttemptId,
    });

    if (!approval) {
      res.status(404).json({ error: 'Approval request not found' });
      return;
    }
    if (approval.status !== 'APPROVED') {
      res.status(400).json({ error: `Approval not granted (status: ${approval.status})` });
      return;
    }
    if (approval.requestingDeviceId !== deviceId) {
      res.status(400).json({ error: 'Device mismatch' });
      return;
    }
    if (approval.expiresAt < new Date()) {
      res.status(410).json({ error: 'Approval has expired' });
      return;
    }

    // Find DeviceProfile — must still be PENDING
    const profile = await DeviceProfile.findOne({ userId: userObjId, deviceId });
    if (!profile || profile.status !== 'PENDING') {
      res.status(409).json({ error: profile ? `Device is already ${profile.status}` : 'Device profile not found' });
      return;
    }

    // Verify fresh signature against STORED key — never client-supplied
    const storedKey = JSON.parse(profile.dbkPublicKey) as object;
    const sigValid  = verifyDbkSignature(storedKey, challengeData.challenge, signature);

    console.log(`[DBK-FINALIZE] Sig valid: ${sigValid}  deviceId: ${deviceId}`);

    if (!sigValid) {
      await logger.audit({ event: 'FINALIZE_INVALID_SIGNATURE', severity: 'CRITICAL', userId, username, deviceId, ip, userAgent: ua, message: 'Invalid signature at finalization — possible key mismatch', attackVector: 'forged_dbk', mitigated: true });
      await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'FAILED', outcome: 'FAILED_DBK', latency: { totalMs: totalTimer.elapsed() }, errorMessage: 'DBK signature verification failed at finalization', errorStep: 'FINALIZE' });
      res.status(403).json({ error: 'Invalid DBK signature' });
      return;
    }

    // Promote DeviceProfile to TRUSTED
    await DeviceProfile.updateOne(
      { _id: profile._id },
      { $set: {
        status:          'TRUSTED',
        approvedBy:      { deviceId: approval.approverDeviceId, approvedAt: new Date() },
        lastAuthSignals: { ...collectSignals(req, {}), loginAt: new Date() },
        updatedAt:       new Date(),
      }},
    );

    // Mark ApprovalRequest CONSUMED to prevent replay
    approval.status     = 'CONSUMED';
    approval.resolvedAt = new Date();
    await approval.save();

    req.session.authenticated = { userId, username, deviceId, deviceStatus: 'TRUSTED', authenticatedAt: Date.now() };
    delete req.session.passkeyVerified;

    const deviceTotalMs = totalTimer.elapsed();
    await logger.audit({ event: 'DEVICE_APPROVED', severity: 'INFO', userId, username, deviceId, ip, userAgent: ua, message: `Device finalized as TRUSTED after approval by ${approval.approverDeviceId}`, details: { approverDeviceId: approval.approverDeviceId } });
    await logger.authAttempt({ userId, username, deviceId, ip, userAgent: ua, flow: 'NEWLY_APPROVED', outcome: 'SUCCESS', latency: { deviceTotalMs, totalMs: deviceTotalMs } });

    res.json({ flow: 'NEWLY_APPROVED', status: 'TRUSTED', deviceId, authComplete: true });
  } catch (err) {
    console.error('[device] finalize error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

export default router;
