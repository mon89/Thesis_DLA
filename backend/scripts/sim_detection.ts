/**
 * DLA Detection Simulation
 * 4 use cases × ITERATIONS each — computes detection and false-positive rates.
 *
 * UC1: Legitimate trusted login          → expected ALLOW (benign)
 * UC2: Legitimate new device + approval  → expected ALLOW (benign)
 * UC3: Cloud compromise attack           → expected BLOCK (adversarial)
 * UC4: Approval denial by trusted user   → expected BLOCK (adversarial)
 *
 * Run: ITERATIONS=30 npx ts-node scripts/sim_detection.ts
 */

import crypto from 'crypto';
import fs from 'fs';

const BASE_URL   = process.env.TEST_URL   ?? 'https://dla.metaauth.site';
const ITERATIONS = parseInt(process.env.ITERATIONS ?? '10', 10);
const RUN_ID     = crypto.randomBytes(4).toString('hex');

// ── CookieJar ────────────────────────────────────────────────────────────────

class CookieJar {
  private cookies: Map<string, string> = new Map();

  absorb(headers: Headers): void {
    let raw: string[] = headers.getSetCookie?.() ?? [];
    if (!raw.length) {
      const joined = headers.get('set-cookie');
      if (joined) raw = joined.split(/,(?=\s*\w+=)/);
    }
    for (const entry of raw) {
      const [pair] = entry.split(';');
      if (!pair) continue;
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  clone(): CookieJar {
    const j = new CookieJar();
    this.cookies.forEach((v, k) => j.cookies.set(k, v));
    return j;
  }
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function baseHeaders(jar: CookieJar, extra: Record<string, string> = {}): Record<string, string> {
  return { 'X-Forwarded-Proto': 'https', Cookie: jar.header(), ...extra };
}

async function apiPost<T>(p: string, body: object, jar: CookieJar): Promise<{ data: T; status: number }> {
  const res = await fetch(`${BASE_URL}${p}`, {
    method: 'POST',
    headers: baseHeaders(jar, { 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });
  jar.absorb(res.headers);
  return { data: await res.json() as T, status: res.status };
}

async function apiGet<T>(p: string, jar: CookieJar): Promise<{ data: T; status: number }> {
  const res = await fetch(`${BASE_URL}${p}`, { headers: baseHeaders(jar) });
  jar.absorb(res.headers);
  return { data: await res.json() as T, status: res.status };
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

interface KeyPair { privateKey: crypto.KeyObject; jwk: JsonWebKey; deviceId: string }

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj as object).sort())
      out[k] = sortKeys((obj as Record<string, unknown>)[k]);
    return out;
  }
  return obj;
}

function genKeyPair(): KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;
  const deviceId = crypto.createHash('sha256')
    .update(JSON.stringify(sortKeys(jwk as Record<string, unknown>)))
    .digest('hex');
  return { privateKey, jwk, deviceId };
}

function sign(privateKey: crypto.KeyObject, challenge: string): string {
  return crypto
    .sign('sha256', Buffer.from(challenge, 'base64url'), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64url');
}

// ── Shared primitives ─────────────────────────────────────────────────────────

async function simulatePasskey(jar: CookieJar, username: string): Promise<void> {
  const { data, status } = await apiPost<{ userId: string; error?: string }>(
    '/api/test/simulate-passkey', { username }, jar,
  );
  if (status !== 200 || data.error)
    throw new Error(`simulate-passkey [${status}]: ${JSON.stringify(data)}`);
}

interface VerifyResult {
  flow?:             string;
  status?:           string;
  authComplete?:     boolean;
  approvalRequired?: boolean;
  approvalGranted?:  boolean;
  requestId?:        string;
  loginAttemptId?:   string;
  error?:            string;
}

async function challengeAndVerify(
  kp:  KeyPair,
  jar: CookieJar,
): Promise<{ result: VerifyResult; httpStatus: number }> {
  // dbkPublicKey goes to /challenge (non-blind challenge flow)
  const { data: ch, status: s1 } = await apiPost<{ challenge?: string; error?: string }>(
    '/api/device/challenge', { dbkPublicKey: kp.jwk }, jar,
  );
  if (s1 !== 200 || !ch.challenge)
    throw new Error(`/challenge [${s1}]: ${JSON.stringify(ch)}`);

  const { data, status } = await apiPost<VerifyResult>(
    '/api/device/verify',
    {
      signature:     sign(kp.privateKey, ch.challenge),
      signals:       { platform: 'sim-script', timezone: 'UTC' },
      clientMetrics: { dbkGenMs: 10, dbkSignMs: 5, totalMs: 80 },
    },
    jar,
  );
  return { result: data, httpStatus: status };
}

function resolveOutcome(result: VerifyResult, httpStatus: number): 'ALLOW' | 'BLOCK' {
  if (httpStatus === 403)        return 'BLOCK';
  if (result.authComplete)       return 'ALLOW';
  if (result.approvalRequired)   return 'BLOCK';
  if (result.flow === 'BLOCKED') return 'BLOCK';
  return 'BLOCK';
}

// ── Use case runners ──────────────────────────────────────────────────────────

async function uc1_legitimateTrustedLogin(i: number): Promise<'ALLOW' | 'BLOCK'> {
  const u  = `${RUN_ID}_uc1_${i}@dla.sim`;
  const kp = genKeyPair();

  const j1 = new CookieJar();
  await simulatePasskey(j1, u);
  const { result: r1 } = await challengeAndVerify(kp, j1);
  if (!r1.authComplete) throw new Error(`bootstrap failed: ${JSON.stringify(r1)}`);

  const j2 = new CookieJar();
  await simulatePasskey(j2, u);
  const { result, httpStatus } = await challengeAndVerify(kp, j2);
  return resolveOutcome(result, httpStatus);
}

async function uc2_legitimateNewDevice(i: number): Promise<'ALLOW' | 'BLOCK'> {
  const u   = `${RUN_ID}_uc2_${i}@dla.sim`;
  const kp1 = genKeyPair();
  const kp2 = genKeyPair();

  // Bootstrap device 1
  const j1 = new CookieJar();
  await simulatePasskey(j1, u);
  const { result: r1 } = await challengeAndVerify(kp1, j1);
  if (!r1.authComplete) throw new Error(`bootstrap failed: ${JSON.stringify(r1)}`);

  // Device 2 requests access → NEW_DEVICE, PENDING
  const j2 = new CookieJar();
  await simulatePasskey(j2, u);
  const { result: r2 } = await challengeAndVerify(kp2, j2);
  if (!r2.approvalRequired) throw new Error(`expected approvalRequired: ${JSON.stringify(r2)}`);
  const { requestId, loginAttemptId } = r2;
  if (!requestId || !loginAttemptId) throw new Error(`missing ids: ${JSON.stringify(r2)}`);

  // Trusted device (device 1) authenticates and approves
  const jA = new CookieJar();
  await simulatePasskey(jA, u);
  await challengeAndVerify(kp1, jA);
  const { data: pending } = await apiGet<{ pending: { requestId: string }[] }>(
    '/api/device/approval/pending', jA,
  );
  const req = pending.pending[0];
  if (!req) throw new Error('no pending approval');
  await apiPost('/api/device/approval/decide', { requestId: req.requestId, decision: 'APPROVED' }, jA);

  // Device 2 finalizes: fresh /challenge then /finalize
  // j2 still has passkeyVerified — NEW_DEVICE flow does not clear it
  const { data: ch2, status: chSt } = await apiPost<{ challenge?: string; error?: string }>(
    '/api/device/challenge', { dbkPublicKey: kp2.jwk }, j2,
  );
  if (chSt !== 200 || !ch2.challenge)
    throw new Error(`/challenge (finalize) [${chSt}]: ${JSON.stringify(ch2)}`);

  const { data: fin, status: finSt } = await apiPost<VerifyResult>(
    '/api/device/finalize',
    { requestId, loginAttemptId, signature: sign(kp2.privateKey, ch2.challenge) },
    j2,
  );
  return resolveOutcome(fin, finSt);
}

async function uc3_cloudCompromise(i: number): Promise<'ALLOW' | 'BLOCK'> {
  const u          = `${RUN_ID}_uc3_${i}@dla.sim`;
  const kpLegit    = genKeyPair();
  const kpAttacker = genKeyPair();

  const j1 = new CookieJar();
  await simulatePasskey(j1, u);
  const { result: r1 } = await challengeAndVerify(kpLegit, j1);
  if (!r1.authComplete) throw new Error(`bootstrap failed: ${JSON.stringify(r1)}`);

  // Attacker: stolen passkey credential, foreign device key
  const jA = new CookieJar();
  await simulatePasskey(jA, u);
  const { result, httpStatus } = await challengeAndVerify(kpAttacker, jA);
  return resolveOutcome(result, httpStatus);
}

async function uc4_approvalDenial(i: number): Promise<'ALLOW' | 'BLOCK'> {
  const u         = `${RUN_ID}_uc4_${i}@dla.sim`;
  const kp1       = genKeyPair();
  const kpSuspect = genKeyPair();

  const j1 = new CookieJar();
  await simulatePasskey(j1, u);
  const { result: r1 } = await challengeAndVerify(kp1, j1);
  if (!r1.authComplete) throw new Error(`bootstrap failed: ${JSON.stringify(r1)}`);

  const jS = new CookieJar();
  await simulatePasskey(jS, u);
  const { result: r2 } = await challengeAndVerify(kpSuspect, jS);
  if (!r2.approvalRequired) throw new Error(`expected approvalRequired: ${JSON.stringify(r2)}`);

  const jA = new CookieJar();
  await simulatePasskey(jA, u);
  await challengeAndVerify(kp1, jA);
  const { data: pending } = await apiGet<{ pending: { requestId: string }[] }>(
    '/api/device/approval/pending', jA,
  );
  const req = pending.pending[0];
  if (!req) throw new Error('no pending approval');
  await apiPost('/api/device/approval/decide', { requestId: req.requestId, decision: 'DENIED' }, jA);

  // Suspect device retries — must be BLOCKED (REJECTED)
  const jRetry = new CookieJar();
  await simulatePasskey(jRetry, u);
  const { result, httpStatus } = await challengeAndVerify(kpSuspect, jRetry);
  return resolveOutcome(result, httpStatus);
}

// ── Statistics helper ─────────────────────────────────────────────────────────

function pct(sorted: number[], p: number): number {
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0;
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface IterResult {
  iteration: number;
  outcome:   'ALLOW' | 'BLOCK';
  expected:  'ALLOW' | 'BLOCK';
  correct:   boolean;
  latencyMs: number;
  error?:    string | undefined;
}

interface UCResult {
  id:        string;
  name:      string;
  type:      'benign' | 'adversarial';
  expected:  'ALLOW' | 'BLOCK';
  correct:   number;
  incorrect: number;
  accuracy:  number;
  latency:   { min: number; max: number; mean: number; p50: number; p95: number };
  iterations: IterResult[];
}

// ── USE_CASES ─────────────────────────────────────────────────────────────────

const USE_CASES: Array<{
  id:       string;
  name:     string;
  type:     'benign' | 'adversarial';
  expected: 'ALLOW' | 'BLOCK';
  runner:   (i: number) => Promise<'ALLOW' | 'BLOCK'>;
}> = [
  { id: 'UC1', name: 'Legitimate trusted login',            type: 'benign',      expected: 'ALLOW', runner: uc1_legitimateTrustedLogin },
  { id: 'UC2', name: 'Legitimate new device with approval', type: 'benign',      expected: 'ALLOW', runner: uc2_legitimateNewDevice     },
  { id: 'UC3', name: 'Cloud compromise attack',             type: 'adversarial', expected: 'BLOCK', runner: uc3_cloudCompromise         },
  { id: 'UC4', name: 'Approval denial by trusted user',     type: 'adversarial', expected: 'BLOCK', runner: uc4_approvalDenial          },
];

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const totalIter = ITERATIONS * USE_CASES.length;

  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  DLA Detection Simulation                            ║');
  console.log(`║  ${ITERATIONS} iterations × ${USE_CASES.length} use cases = ${totalIter} total`.padEnd(54) + '║');
  console.log(`║  Run ID : ${RUN_ID}`.padEnd(54) + '║');
  console.log(`║  Target : ${BASE_URL}`.padEnd(54) + '║');
  console.log('╚══════════════════════════════════════════════════════╝');

  const ucResults: UCResult[] = [];

  for (const uc of USE_CASES) {
    console.log(`\n▶ ${uc.id}: ${uc.name}  [${uc.type}, expected=${uc.expected}]`);
    const iterations: IterResult[] = [];

    for (let i = 1; i <= ITERATIONS; i++) {
      const t0 = Date.now();
      let out: 'ALLOW' | 'BLOCK';
      let err: string | undefined;
      try {
        out = await uc.runner(i);
      } catch (e) {
        out = 'BLOCK';
        err = String(e).slice(0, 100);
      }
      const latencyMs = Date.now() - t0;
      const correct   = out === uc.expected;
      iterations.push({ iteration: i, outcome: out, expected: uc.expected, correct, latencyMs, error: err });
      process.stdout.write(correct ? '.' : 'F');
      if (i % 10 === 0) process.stdout.write(` ${i}\n`);
    }
    if (ITERATIONS % 10 !== 0) process.stdout.write('\n');

    const correct   = iterations.filter(r => r.correct).length;
    const lats      = iterations.map(r => r.latencyMs).sort((a, b) => a - b);
    const mean      = Math.round(lats.reduce((s, v) => s + v, 0) / lats.length);
    const ucr: UCResult = {
      id: uc.id, name: uc.name, type: uc.type, expected: uc.expected,
      correct,
      incorrect: ITERATIONS - correct,
      accuracy:  Math.round((correct / ITERATIONS) * 10000) / 100,
      latency: {
        min: lats[0] ?? 0,
        max: lats[lats.length - 1] ?? 0,
        mean,
        p50: pct(lats, 50),
        p95: pct(lats, 95),
      },
      iterations,
    };
    ucResults.push(ucr);
    console.log(
      `  ${ucr.correct}/${ITERATIONS} correct  (${ucr.accuracy}%)` +
      `  p50=${ucr.latency.p50}ms  p95=${ucr.latency.p95}ms`,
    );
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  const adv = ucResults.filter(r => r.type === 'adversarial');
  const ben = ucResults.filter(r => r.type === 'benign');
  const tp  = adv.reduce((s, r) => s + r.correct, 0);
  const fn  = adv.reduce((s, r) => s + r.incorrect, 0);
  const tn  = ben.reduce((s, r) => s + r.correct, 0);
  const fp  = ben.reduce((s, r) => s + r.incorrect, 0);

  const detRate  = Math.round((tp / (tp + fn || 1)) * 10000) / 100;
  const fpRate   = Math.round((fp / (fp + tn || 1)) * 10000) / 100;
  const accuracy = Math.round(((tp + tn) / (tp + fn + tn + fp || 1)) * 10000) / 100;

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  RESULTS                                             ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  for (const r of ucResults) {
    const icon = r.correct === ITERATIONS ? '✓' : '✗';
    const line = `  ${icon} ${r.id}  ${r.name.padEnd(36)}  ${r.correct}/${ITERATIONS}`;
    console.log(`║${line.padEnd(54)}║`);
  }
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Total iterations:    ${totalIter}`.padEnd(54) + '║');
  console.log(`║  Detection Rate:      ${detRate}%`.padEnd(54) + '║');
  console.log(`║  False Positive Rate: ${fpRate}%`.padEnd(54) + '║');
  console.log(`║  Overall Accuracy:    ${accuracy}%`.padEnd(54) + '║');
  console.log('╚══════════════════════════════════════════════════════╝');

  // ── Save report ───────────────────────────────────────────────────────────
  const report = {
    timestamp:       new Date().toISOString(),
    baseUrl:         BASE_URL,
    runId:           RUN_ID,
    iterationsPerUc: ITERATIONS,
    totalIterations: totalIter,
    useCases:        ucResults,
    summary:         { detectionRate: detRate, falsePositiveRate: fpRate, overallAccuracy: accuracy, tp, fn, tn, fp },
  };

  const fname = `detection_results_${Date.now()}.json`;
  fs.writeFileSync(fname, JSON.stringify(report, null, 2));
  console.log(`\n  Results saved → ${fname}`);
}

main().catch(err => {
  console.error('[fatal]', err);
  process.exit(1);
});
