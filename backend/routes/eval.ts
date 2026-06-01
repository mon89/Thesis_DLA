import { Router, type Request, type Response } from 'express';
import { AuthenticationLog } from '../models/AuthenticationLog';
import { SessionLog } from '../models/SessionLog';
import { AuditLog } from '../models/AuditLog';

const router = Router();

// ── Percentile helper ─────────────────────────────────────────────────────────

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  const val = sorted[Math.max(0, idx)];
  return val !== undefined ? Math.round(val * 100) / 100 : 0;
}

function stats(values: number[]) {
  if (values.length === 0) return { p50: 0, p95: 0, p99: 0, mean: 0, min: 0, max: 0, count: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const sum    = sorted.reduce((a, b) => a + b, 0);
  return {
    p50:   percentile(sorted, 50),
    p95:   percentile(sorted, 95),
    p99:   percentile(sorted, 99),
    mean:  Math.round((sum / sorted.length) * 100) / 100,
    min:   sorted[0] ?? 0,
    max:   sorted[sorted.length - 1] ?? 0,
    count: sorted.length,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. GET /api/eval/latency
//    P50/P95/P99 for every latency dimension across successful auth attempts
// ─────────────────────────────────────────────────────────────────────────────
router.get('/latency', async (_req: Request, res: Response) => {
  try {
    const logs = await AuthenticationLog.find({ outcome: 'SUCCESS' }, { latency: 1 }).lean();

    const fields = [
      'passkeyOptionsMs', 'passkeyVerifyMs', 'passkeyTotalMs',
      'challengeMs', 'dbkVerifyMs', 'deviceLookupMs', 'deviceTotalMs',
      'totalMs', 'clientDbkGenMs', 'clientDbkSignMs', 'clientTotalMs',
    ] as const;

    const result: Record<string, ReturnType<typeof stats>> = {};

    for (const field of fields) {
      const values = logs
        .map(l => l.latency[field])
        .filter((v): v is number => v !== undefined && v !== null && isFinite(v));
      result[field] = stats(values);
    }

    res.json({ sampleSize: logs.length, latency: result });
  } catch (err) {
    console.error('[eval] latency error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. GET /api/eval/flows
//    Counts and success rates grouped by flow + outcome
// ─────────────────────────────────────────────────────────────────────────────
router.get('/flows', async (_req: Request, res: Response) => {
  try {
    const agg = await AuthenticationLog.aggregate<{
      _id:     { flow: string; outcome: string };
      count:   number;
    }>([
      { $group: { _id: { flow: '$flow', outcome: '$outcome' }, count: { $sum: 1 } } },
      { $sort:  { '_id.flow': 1, '_id.outcome': 1 } },
    ]);

    // Summarise per flow
    const flowMap: Record<string, { total: number; success: number; outcomes: Record<string, number> }> = {};
    for (const row of agg) {
      const { flow, outcome } = row._id;
      if (!flowMap[flow]) flowMap[flow] = { total: 0, success: 0, outcomes: {} };
      const entry = flowMap[flow]!;
      entry.total += row.count;
      entry.outcomes[outcome] = row.count;
      if (outcome === 'SUCCESS') entry.success += row.count;
    }

    const flows = Object.entries(flowMap).map(([flow, d]) => ({
      flow,
      total:       d.total,
      success:     d.success,
      successRate: d.total > 0 ? Math.round((d.success / d.total) * 10000) / 100 : 0,
      outcomes:    d.outcomes,
    }));

    const total   = flows.reduce((s, f) => s + f.total,   0);
    const success = flows.reduce((s, f) => s + f.success, 0);

    res.json({
      total,
      overallSuccessRate: total > 0 ? Math.round((success / total) * 10000) / 100 : 0,
      flows,
    });
  } catch (err) {
    console.error('[eval] flows error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. GET /api/eval/security
//    Security event counts and attack mitigation rate
// ─────────────────────────────────────────────────────────────────────────────
router.get('/security', async (_req: Request, res: Response) => {
  try {
    const [auditCounts, expiredApprovals, sessionMismatches] = await Promise.all([
      AuditLog.aggregate<{ _id: string; count: number }>([
        { $group: { _id: '$event', count: { $sum: 1 } } },
      ]),
      AuditLog.countDocuments({ event: 'APPROVAL_EXPIRED' }),
      SessionLog.countDocuments({ event: 'DEVICE_MISMATCH' }),
    ]);

    const byEvent: Record<string, number> = {};
    for (const row of auditCounts) byEvent[row._id] = row.count;

    const totalAttacks  = (byEvent['DBK_SIGNATURE_INVALID'] ?? 0)
                        + (byEvent['DEVICE_BLOCKED'] ?? 0)
                        + sessionMismatches;
    const mitigated     = await AuditLog.countDocuments({ mitigated: true });
    const totalAudit    = await AuditLog.countDocuments();
    const mitigationRate = totalAudit > 0
      ? Math.round((mitigated / totalAudit) * 10000) / 100
      : 100;

    res.json({
      blockedDevices:         byEvent['DEVICE_BLOCKED']          ?? 0,
      invalidSignatures:      byEvent['DBK_SIGNATURE_INVALID']   ?? 0,
      approvals:              byEvent['DEVICE_APPROVED']          ?? 0,
      denials:                byEvent['DEVICE_DENIED']            ?? 0,
      expiredApprovals,
      sessionMismatches,
      challengeExpired:       byEvent['DBK_CHALLENGE_EXPIRED']   ?? 0,
      totalAttackAttempts:    totalAttacks,
      mitigationRate:         `${mitigationRate}%`,
    });
  } catch (err) {
    console.error('[eval] security error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. GET /api/eval/sessions
//    Session event breakdown and device binding effectiveness
// ─────────────────────────────────────────────────────────────────────────────
router.get('/sessions', async (_req: Request, res: Response) => {
  try {
    const agg = await SessionLog.aggregate<{ _id: string; count: number }>([
      { $group: { _id: '$event', count: { $sum: 1 } } },
      { $sort:  { count: -1 } },
    ]);

    const byEvent: Record<string, number> = {};
    for (const row of agg) byEvent[row._id] = row.count;

    const total          = Object.values(byEvent).reduce((s, n) => s + n, 0);
    const mismatches     = byEvent['DEVICE_MISMATCH'] ?? 0;
    const verified       = byEvent['DEVICE_VERIFIED'] ?? 0;
    const bindingRate    = (verified + mismatches) > 0
      ? Math.round((verified / (verified + mismatches)) * 10000) / 100
      : 100;

    res.json({
      total,
      byEvent,
      deviceMismatches:         mismatches,
      bindingEffectivenessRate: `${bindingRate}%`,
    });
  } catch (err) {
    console.error('[eval] sessions error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. GET /api/eval/export
//    CSV export of all successful authentication logs
// ─────────────────────────────────────────────────────────────────────────────
router.get('/export', async (_req: Request, res: Response) => {
  try {
    const logs = await AuthenticationLog.find(
      { outcome: 'SUCCESS' },
      { createdAt: 1, username: 1, flow: 1, latency: 1 },
    ).sort({ createdAt: 1 }).lean();

    const header = [
      'timestamp', 'username', 'flow',
      'passkey_options_ms', 'passkey_verify_ms', 'passkey_total_ms',
      'challenge_ms', 'dbk_verify_ms', 'device_lookup_ms', 'device_total_ms',
      'total_ms',
      'client_dbk_gen_ms', 'client_dbk_sign_ms', 'client_total_ms',
    ].join(',');

    const rows = logs.map(l => [
      l.createdAt.toISOString(),
      escapeCsv(l.username ?? ''),
      escapeCsv(l.flow),
      l.latency.passkeyOptionsMs  ?? '',
      l.latency.passkeyVerifyMs   ?? '',
      l.latency.passkeyTotalMs    ?? '',
      l.latency.challengeMs       ?? '',
      l.latency.dbkVerifyMs       ?? '',
      l.latency.deviceLookupMs    ?? '',
      l.latency.deviceTotalMs     ?? '',
      l.latency.totalMs           ?? '',
      l.latency.clientDbkGenMs    ?? '',
      l.latency.clientDbkSignMs   ?? '',
      l.latency.clientTotalMs     ?? '',
    ].join(','));

    const csv = [header, ...rows].join('\r\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="dla_auth_log.csv"');
    res.send(csv);
  } catch (err) {
    console.error('[eval] export error:', err);
    res.status(500).json({ error: 'internal server error' });
  }
});

function escapeCsv(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export default router;
