import mongoose from 'mongoose';
import { AuthenticationLog, type AuthFlow, type AuthOutcome } from '../models/AuthenticationLog';
import { SessionLog, type SessionEvent } from '../models/SessionLog';
import { AuditLog, type AuditEvent, type AuditSeverity } from '../models/AuditLog';

// ── Timer ─────────────────────────────────────────────────────────────────────

export interface Timer {
  elapsed(): number;
}

export function startTimer(): Timer {
  const start = process.hrtime.bigint();
  return {
    elapsed(): number {
      return Number(process.hrtime.bigint() - start) / 1_000_000;
    },
  };
}

// ── Latency shape ─────────────────────────────────────────────────────────────
// All fields use `?: T | undefined` so callers can spread objects that contain
// undefined values without violating exactOptionalPropertyTypes.

export interface LatencyData {
  passkeyOptionsMs?: number | undefined;
  passkeyVerifyMs?:  number | undefined;
  passkeyTotalMs?:   number | undefined;
  challengeMs?:      number | undefined;
  dbkVerifyMs?:      number | undefined;
  deviceLookupMs?:   number | undefined;
  deviceTotalMs?:    number | undefined;
  totalMs?:          number | undefined;
  clientDbkGenMs?:   number | undefined;
  clientDbkSignMs?:  number | undefined;
  clientTotalMs?:    number | undefined;
}

// ── Data shapes ───────────────────────────────────────────────────────────────

export interface AuthAttemptData {
  userId?:       string | undefined;
  username?:     string | undefined;
  deviceId?:     string | undefined;
  ip?:           string | undefined;
  userAgent?:    string | undefined;
  flow:          AuthFlow;
  outcome:       AuthOutcome;
  latency?:      LatencyData;
  errorMessage?: string | undefined;
  errorStep?:    string | undefined;
}

export interface SessionEventData {
  sessionId:          string;
  userId?:            string | undefined;
  username?:          string | undefined;
  deviceId?:          string | undefined;
  event:              SessionEvent;
  ip?:                string | undefined;
  userAgent?:         string | undefined;
  timezone?:          string | undefined;
  expectedDeviceId?:  string | undefined;
  actualDeviceId?:    string | undefined;
}

export interface AuditData {
  event:          AuditEvent;
  severity?:      AuditSeverity | undefined;
  userId?:        string | undefined;
  username?:      string | undefined;
  deviceId?:      string | undefined;
  message:        string;
  details?:       unknown;
  ip?:            string | undefined;
  userAgent?:     string | undefined;
  attackVector?:  string | undefined;
  mitigated?:     boolean | undefined;
}

// ── Core log functions ────────────────────────────────────────────────────────

async function authAttempt(data: AuthAttemptData): Promise<void> {
  try {
    await new AuthenticationLog({
      userId:       data.userId ? new mongoose.Types.ObjectId(data.userId) : undefined,
      username:     data.username,
      deviceId:     data.deviceId,
      ip:           data.ip,
      userAgent:    data.userAgent,
      flow:         data.flow,
      outcome:      data.outcome,
      latency:      stripUndefined(data.latency ?? {}),
      errorMessage: data.errorMessage,
      errorStep:    data.errorStep,
    }).save();
  } catch (err) {
    console.error('[logger] authAttempt failed:', err);
  }
}

async function sessionEvent(data: SessionEventData): Promise<void> {
  try {
    await new SessionLog({
      sessionId:        data.sessionId,
      userId:           data.userId ? new mongoose.Types.ObjectId(data.userId) : undefined,
      username:         data.username,
      deviceId:         data.deviceId,
      event:            data.event,
      ip:               data.ip,
      userAgent:        data.userAgent,
      timezone:         data.timezone,
      expectedDeviceId: data.expectedDeviceId,
      actualDeviceId:   data.actualDeviceId,
    }).save();
  } catch (err) {
    console.error('[logger] sessionEvent failed:', err);
  }
}

async function audit(data: AuditData): Promise<void> {
  try {
    await new AuditLog({
      event:        data.event,
      severity:     data.severity ?? 'INFO',
      userId:       data.userId ? new mongoose.Types.ObjectId(data.userId) : undefined,
      username:     data.username,
      deviceId:     data.deviceId,
      message:      data.message,
      details:      data.details,
      ip:           data.ip,
      userAgent:    data.userAgent,
      attackVector: data.attackVector,
      mitigated:    data.mitigated ?? true,
    }).save();
  } catch (err) {
    console.error('[logger] audit failed:', err);
  }
}

// ── Convenience methods ───────────────────────────────────────────────────────

async function deviceBlocked(args: {
  userId:   string;
  username: string;
  deviceId: string;
  ip:       string;
  reason:   string;
}): Promise<void> {
  await audit({
    event:        'DEVICE_BLOCKED',
    severity:     'CRITICAL',
    userId:       args.userId,
    username:     args.username,
    deviceId:     args.deviceId,
    ip:           args.ip,
    message:      `Device blocked: ${args.reason}`,
    attackVector: 'blocked_device',
    mitigated:    true,
  });
}

async function dbkSignatureInvalid(args: {
  userId:   string;
  username: string;
  ip:       string;
}): Promise<void> {
  await audit({
    event:        'DBK_SIGNATURE_INVALID',
    severity:     'CRITICAL',
    userId:       args.userId,
    username:     args.username,
    ip:           args.ip,
    message:      'DBK signature verification failed — possible forged or replayed key',
    attackVector: 'forged_dbk',
    mitigated:    true,
  });
}

async function deviceApproved(args: {
  userId:           string;
  username:         string;
  deviceId:         string;
  approverDeviceId: string;
}): Promise<void> {
  await audit({
    event:    'DEVICE_APPROVED',
    severity: 'INFO',
    userId:   args.userId,
    username: args.username,
    deviceId: args.deviceId,
    message:  `Device ${args.deviceId} approved by ${args.approverDeviceId}`,
    details:  { approverDeviceId: args.approverDeviceId },
  });
}

async function deviceDenied(args: {
  userId:           string;
  username:         string;
  deviceId:         string;
  approverDeviceId: string;
}): Promise<void> {
  await audit({
    event:    'DEVICE_DENIED',
    severity: 'WARNING',
    userId:   args.userId,
    username: args.username,
    deviceId: args.deviceId,
    message:  `Device ${args.deviceId} denied by ${args.approverDeviceId}`,
    details:  { approverDeviceId: args.approverDeviceId },
  });
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/** Remove keys whose value is undefined so exactOptionalPropertyTypes is satisfied. */
function stripUndefined<T extends object>(obj: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  ) as Partial<T>;
}

// ── Exports ───────────────────────────────────────────────────────────────────

export const logger = {
  startTimer,
  authAttempt,
  sessionEvent,
  audit,
  deviceBlocked,
  dbkSignatureInvalid,
  deviceApproved,
  deviceDenied,
};
