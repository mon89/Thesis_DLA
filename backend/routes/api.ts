/// <reference path="../types/express-session-augment.d.ts" />
import { Router, type Request, type Response } from 'express';
import { User } from '../models/User';
import { Credential } from '../models/Credential';
import { Challenge } from '../models/Challenge';
import { DeviceProfile } from '../models/DeviceProfile';
import { ApprovalRequest } from '../models/ApprovalRequest';
import { AuthenticationLog } from '../models/AuthenticationLog';
import { SessionLog } from '../models/SessionLog';
import { AuditLog } from '../models/AuditLog';

const router = Router();

// GET /api/health
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    ok:        true,
    rpId:      process.env.RP_ID,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/session
router.get('/session', (req: Request, res: Response) => {
  const auth = req.session.authenticated;
  const pv   = req.session.passkeyVerified;
  res.json({
    sessionId:     req.session.id,
    userId:        auth?.userId ?? pv?.userId ?? null,
    authenticated: auth != null,
    deviceId:      auth?.deviceId      ?? null,
    deviceStatus:  auth?.deviceStatus  ?? null,
    passkeyVerified: pv != null,
  });
});

// ── DEV/TEST ONLY ─────────────────────────────────────────────────────────────
// POST /api/test/simulate-passkey
// Bypasses WebAuthn Layer 1 to set passkeyVerified in session directly.
// Must NOT be reachable in production.
router.post('/test/simulate-passkey', async (req: Request, res: Response) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(404).json({ error: 'Not found' });
    return;
  }
  try {
    const { username } = req.body as { username?: string };
    if (!username) {
      res.status(400).json({ error: 'username is required' });
      return;
    }
    const email = `${username}@test.local`;
    let user = await User.findOne({ email });
    if (!user) user = await User.create({ email, displayName: username });
    const userId = (user._id as object).toString();
    req.session.passkeyVerified = { userId, username, verifiedAt: Date.now() };
    req.session.save(err => {
      if (err) { res.status(500).json({ error: 'session save failed' }); return; }
      res.json({ userId, username });
    });
  } catch (err) {
    console.error('[test] simulate-passkey error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ── DEV/TEST ONLY ─────────────────────────────────────────────────────────────
// POST /api/test/reset-db
// Clears all collections to give each test run a clean slate.
// Must NOT be reachable in production.
router.post('/test/reset-db', async (_req: Request, res: Response) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(404).json({ error: 'Not found' });
    return;
  }
  try {
    await Promise.all([
      User.deleteMany({}),
      Credential.deleteMany({}),
      Challenge.deleteMany({}),
      DeviceProfile.deleteMany({}),
      ApprovalRequest.deleteMany({}),
      AuthenticationLog.deleteMany({}),
      SessionLog.deleteMany({}),
      AuditLog.deleteMany({}),
    ]);
    res.json({ ok: true, message: 'All collections cleared' });
  } catch (err) {
    console.error('[test] reset-db error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// POST /api/logout
router.post('/logout', (req: Request, res: Response) => {
  req.session.destroy(err => {
    if (err) {
      res.status(500).json({ error: 'Failed to destroy session' });
      return;
    }
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

export default router;
