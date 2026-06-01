/**
 * DLA Full-Flow Test Script
 * Simulates a fake iOS client: generates ECDSA P-256 keys, signs challenges,
 * and exercises all authentication flows end-to-end.
 *
 * Run: npx ts-node scripts/test-flow.ts
 */

import crypto from 'crypto';

// ── Config ────────────────────────────────────────────────────────────────────

const BASE_URL = process.env.TEST_URL ?? 'https://dla.metaauth.site';
const TEST_USER = 'testuser';

// ── Types ─────────────────────────────────────────────────────────────────────

interface KeyPair {
  privateKey: crypto.KeyObject;
  publicKey:  crypto.KeyObject;
  jwk:        JsonWebKey;
  deviceId?:  string;
}

interface TestResult {
  name:    string;
  passed:  boolean;
  error?:  string;
}

const DEBUG = process.env.DEBUG === '1';

// ── Cookie Jar ────────────────────────────────────────────────────────────────
// Parses Set-Cookie headers and replays them as Cookie headers.
// Uses getSetCookie() (Node 20+) with a comma-split fallback.

class CookieJar {
  private cookies: Map<string, string> = new Map();

  absorb(headers: Headers): void {
    // Primary: getSetCookie() returns one entry per Set-Cookie header (Node 20+)
    let raw: string[] = headers.getSetCookie?.() ?? [];

    // Fallback: headers.get() joins multiple Set-Cookie with ', ' — split carefully
    if (raw.length === 0) {
      const joined = headers.get('set-cookie');
      if (joined) raw = joined.split(/,(?=\s*\w+=)/);
    }

    if (DEBUG && raw.length > 0) {
      console.log('      [CookieJar] absorbing:', raw.map(r => r.split(';')[0]).join(' | '));
    }

    for (const entry of raw) {
      const [pair] = entry.split(';');
      if (!pair) continue;
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name  = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      this.cookies.set(name, value);
    }
  }

  header(): string {
    const h = [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    if (DEBUG && h) console.log('      [CookieJar] sending:', h.slice(0, 60));
    return h;
  }

  has(name: string): boolean { return this.cookies.has(name); }

  clone(): CookieJar {
    const j = new CookieJar();
    this.cookies.forEach((v, k) => j.cookies.set(k, v));
    return j;
  }
}

// ── Shared request headers ────────────────────────────────────────────────────
// X-Forwarded-Proto: https tells Express (trust proxy: 1) that the connection
// is HTTPS, so express-session sets the Secure cookie even over HTTP localhost.
// This matches what nginx does in production.

function baseHeaders(jar: CookieJar, extra: Record<string, string> = {}): Record<string, string> {
  return {
    'X-Forwarded-Proto': 'https',
    'Cookie':            jar.header(),
    ...extra,
  };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

async function post<T>(
  path:    string,
  body:    object,
  jar:     CookieJar,
  label?:  string,
): Promise<{ data: T; status: number }> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    method:  'POST',
    headers: baseHeaders(jar, { 'Content-Type': 'application/json' }),
    body:    JSON.stringify(body),
  });
  jar.absorb(res.headers);
  const data = await res.json() as T;
  if (label) console.log(`    ${label} [${res.status}]:`, JSON.stringify(data).slice(0, 120));
  return { data, status: res.status };
}

async function get<T>(
  path:   string,
  jar:    CookieJar,
  label?: string,
): Promise<{ data: T; status: number }> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, { headers: baseHeaders(jar) });
  jar.absorb(res.headers);
  const data = await res.json() as T;
  if (label) console.log(`    ${label} [${res.status}]:`, JSON.stringify(data).slice(0, 120));
  return { data, status: res.status };
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;

  return { privateKey, publicKey, jwk };
}

function signChallenge(privateKey: crypto.KeyObject, challenge: string): string {
  const challengeBuf = Buffer.from(challenge, 'base64url');
  const sig = crypto.sign('sha256', challengeBuf, {
    key:         privateKey,
    dsaEncoding: 'ieee-p1363',  // raw r||s — matches iOS Secure Enclave output
  });
  return sig.toString('base64url');
}

function computeDeviceId(jwk: JsonWebKey): string {
  const sorted = sortKeys(jwk as Record<string, unknown>);
  return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj))          return obj.map(sortKeys);
  if (obj !== null && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj as object).sort())
      out[k] = sortKeys((obj as Record<string, unknown>)[k]);
    return out;
  }
  return obj;
}

// ── Layer 1 bypass ────────────────────────────────────────────────────────────

async function simulatePasskey(jar: CookieJar): Promise<{ userId: string; username: string }> {
  const { data, status } = await post<{ userId: string; username: string; error?: string }>(
    '/api/test/simulate-passkey',
    { username: TEST_USER },
    jar,
  );
  if (status !== 200 || data.error) throw new Error(`simulate-passkey failed: ${JSON.stringify(data)}`);
  return data;
}

// ── Device verify helper ──────────────────────────────────────────────────────

async function deviceVerify(
  kp:  KeyPair,
  jar: CookieJar,
  clientMetrics?: { dbkGenMs: number; dbkSignMs: number; totalMs: number },
): Promise<{ flow: string; status: string; authComplete: boolean; approvalRequired?: boolean }> {
  const { data: ch, status: chStatus } = await post<{
    challenge: string; trustedDeviceCount: number; isBootstrap: boolean; error?: string;
  }>('/api/device/challenge', {}, jar, 'POST /api/device/challenge');
  if (chStatus !== 200 || !ch.challenge) throw new Error(`challenge failed: ${JSON.stringify(ch)}`);

  const signature = signChallenge(kp.privateKey, ch.challenge);
  const { data, status } = await post<{
    flow: string; status: string; authComplete: boolean; approvalRequired?: boolean; error?: string;
  }>(
    '/api/device/verify',
    {
      dbkPublicKey:  kp.jwk,
      signature,
      signals:       { platform: 'test-script', timezone: 'Asia/Tokyo' },
      clientMetrics: clientMetrics ?? { dbkGenMs: 15, dbkSignMs: 8, totalMs: 120 },
    },
    jar,
    'POST /api/device/verify',
  );
  if (status !== 200 && status !== 403) throw new Error(`device/verify failed [${status}]: ${JSON.stringify(data)}`);
  return data as { flow: string; status: string; authComplete: boolean; approvalRequired?: boolean };
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST 1 — BOOTSTRAP
// ═════════════════════════════════════════════════════════════════════════════

async function testBootstrap(): Promise<{ kp: KeyPair; jar: CookieJar }> {
  console.log('\n── TEST 1: BOOTSTRAP (first device) ──');
  const jar = new CookieJar();
  await simulatePasskey(jar);

  const kp = generateKeyPair();
  kp.deviceId = computeDeviceId(kp.jwk);
  console.log(`    Generated key, deviceId: ${kp.deviceId.slice(0, 16)}…`);

  const result = await deviceVerify(kp, jar, { dbkGenMs: 15, dbkSignMs: 8, totalMs: 110 });

  if (result.flow !== 'BOOTSTRAP' || result.authComplete !== true)
    throw new Error(`Unexpected result: ${JSON.stringify(result)}`);

  const { data: list } = await get<{ devices: { deviceId: string; status: string }[] }>(
    '/api/device/list', jar, 'GET /api/device/list',
  );
  const trusted = list.devices.filter(d => d.status === 'TRUSTED');
  if (trusted.length < 1) throw new Error('Expected at least 1 TRUSTED device in list');

  console.log('  ✓ BOOTSTRAP flow passed');
  return { kp, jar };
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST 2 — TRUSTED DEVICE
// ═════════════════════════════════════════════════════════════════════════════

async function testTrustedDevice(kp: KeyPair, trustedJar: CookieJar): Promise<void> {
  console.log('\n── TEST 2: TRUSTED DEVICE (same key logs in again) ──');

  // New independent session — simulate-passkey sets passkeyVerified
  const jar = trustedJar.clone();
  await simulatePasskey(jar);

  const result = await deviceVerify(kp, jar, { dbkGenMs: 13, dbkSignMs: 7, totalMs: 105 });

  if (result.flow !== 'TRUSTED_DEVICE' || result.authComplete !== true)
    throw new Error(`Unexpected result: ${JSON.stringify(result)}`);

  console.log('  ✓ TRUSTED_DEVICE flow passed');
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST 3 — NEW DEVICE + APPROVAL
// ═════════════════════════════════════════════════════════════════════════════

async function testNewDeviceApproval(trustedKp: KeyPair, trustedJar: CookieJar): Promise<void> {
  console.log('\n── TEST 3: NEW DEVICE + APPROVAL ──');

  // New device session
  const newJar = new CookieJar();
  await simulatePasskey(newJar);

  const newKp = generateKeyPair();
  newKp.deviceId = computeDeviceId(newKp.jwk);
  console.log(`    New device id: ${newKp.deviceId.slice(0, 16)}…`);

  const result = await deviceVerify(newKp, newJar, { dbkGenMs: 18, dbkSignMs: 10, totalMs: 130 });
  if (result.flow !== 'NEW_DEVICE' || result.approvalRequired !== true)
    throw new Error(`Expected NEW_DEVICE pending, got: ${JSON.stringify(result)}`);

  // Re-authenticate trusted device to get a fresh authenticated session
  const approverJar = trustedJar.clone();
  await simulatePasskey(approverJar);
  await deviceVerify(trustedKp, approverJar, { dbkGenMs: 12, dbkSignMs: 7, totalMs: 100 });

  // Fetch pending approvals from trusted device
  const { data: pendingData } = await get<{
    pending: { requestId: string; requestingDeviceId: string }[];
  }>('/api/device/approval/pending', approverJar, 'GET /api/device/approval/pending');

  if (!pendingData.pending.length)
    throw new Error('Expected at least 1 pending approval');

  const req0 = pendingData.pending[0];
  if (!req0) throw new Error('No pending request found');
  console.log(`    Approving requestId: ${req0.requestId}`);

  const { data: decision, status: dStatus } = await post<{ decision: string; message: string }>(
    '/api/device/approval/decide',
    { requestId: req0.requestId, decision: 'APPROVED' },
    approverJar,
    'POST /api/device/approval/decide',
  );
  if (dStatus !== 200) throw new Error(`approval/decide failed: ${JSON.stringify(decision)}`);

  // Check new device status
  const { data: statusData } = await get<{ deviceId: string; status: string }>(
    `/api/device/status/${newKp.deviceId}`,
    approverJar,
    'GET /api/device/status/:id',
  );
  if (statusData.status !== 'TRUSTED')
    throw new Error(`Expected TRUSTED after approval, got: ${statusData.status}`);

  console.log('  ✓ NEW_DEVICE + APPROVAL flow passed');
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST 4 — BLOCKED (denied device tries again)
// ═════════════════════════════════════════════════════════════════════════════

async function testBlocked(trustedKp: KeyPair, trustedJar: CookieJar): Promise<void> {
  console.log('\n── TEST 4: BLOCKED (denied device) ──');

  // Enroll new device → NEW_DEVICE
  const blockedJar = new CookieJar();
  await simulatePasskey(blockedJar);
  const blockedKp = generateKeyPair();
  blockedKp.deviceId = computeDeviceId(blockedKp.jwk);
  console.log(`    Blocked device id: ${blockedKp.deviceId.slice(0, 16)}…`);

  const r1 = await deviceVerify(blockedKp, blockedJar, { dbkGenMs: 14, dbkSignMs: 9, totalMs: 115 });
  if (r1.flow !== 'NEW_DEVICE') throw new Error(`Expected NEW_DEVICE, got: ${r1.flow}`);

  // Trusted device DENIES the request
  const approverJar = trustedJar.clone();
  await simulatePasskey(approverJar);
  await deviceVerify(trustedKp, approverJar, { dbkGenMs: 12, dbkSignMs: 7, totalMs: 100 });

  const { data: pendingData } = await get<{
    pending: { requestId: string }[];
  }>('/api/device/approval/pending', approverJar, 'GET /api/device/approval/pending');

  const req0 = pendingData.pending[0];
  if (!req0) throw new Error('No pending request for blocked device');

  await post('/api/device/approval/decide',
    { requestId: req0.requestId, decision: 'DENIED' },
    approverJar,
    'POST /api/device/approval/decide (DENIED)',
  );

  // Blocked device tries to authenticate again
  await simulatePasskey(blockedJar);
  const r2 = await deviceVerify(blockedKp, blockedJar, { dbkGenMs: 14, dbkSignMs: 9, totalMs: 115 });
  if (r2.flow !== 'BLOCKED')
    throw new Error(`Expected BLOCKED, got: ${JSON.stringify(r2)}`);

  console.log('  ✓ BLOCKED flow passed');
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST 5 — EVALUATION ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

async function testEvalEndpoints(): Promise<void> {
  console.log('\n── TEST 5: EVALUATION ENDPOINTS ──');
  const jar = new CookieJar();

  const { data: latency, status: s1 } = await get<{
    sampleSize: number;
    latency: Record<string, { p50: number; p95: number; mean: number; count: number }>;
  }>('/api/eval/latency', jar, 'GET /api/eval/latency');
  if (s1 !== 200) throw new Error(`/api/eval/latency returned ${s1}`);
  console.log(`    Sample size: ${latency.sampleSize}`);
  const totalMs = latency.latency['totalMs'];
  if (totalMs && totalMs.count > 0) {
    console.log(`    totalMs — p50: ${totalMs.p50}ms  p95: ${totalMs.p95}ms  mean: ${totalMs.mean}ms`);
  }

  const { data: flows, status: s2 } = await get<{
    total: number;
    overallSuccessRate: number;
    flows: { flow: string; total: number; successRate: number }[];
  }>('/api/eval/flows', jar, 'GET /api/eval/flows');
  if (s2 !== 200) throw new Error(`/api/eval/flows returned ${s2}`);
  console.log(`    Total auth attempts: ${flows.total}, success rate: ${flows.overallSuccessRate}%`);
  for (const f of flows.flows) {
    console.log(`      ${f.flow.padEnd(20)} total=${f.total}  success=${f.successRate}%`);
  }

  const { data: security, status: s3 } = await get<{
    blockedDevices:      number;
    invalidSignatures:   number;
    mitigationRate:      string;
  }>('/api/eval/security', jar, 'GET /api/eval/security');
  if (s3 !== 200) throw new Error(`/api/eval/security returned ${s3}`);
  console.log(`    Blocked: ${security.blockedDevices}  InvalidSigs: ${security.invalidSignatures}  Mitigation: ${security.mitigationRate}`);

  console.log('  ✓ Evaluation endpoints working');
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════

async function resetDb(): Promise<void> {
  console.log('\n── Resetting database ────────────────────────────────────────────────────');
  const res = await fetch(`${BASE_URL}/api/test/reset-db`, {
    method: 'POST',
    headers: baseHeaders(new CookieJar()),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`reset-db failed: ${res.status} ${body}`);
  }
  const data = await res.json() as { ok: boolean; message?: string };
  console.log(`  ✓ ${data.message ?? 'Database cleared'}`);
}

async function main(): Promise<void> {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║  DLA Full-Flow Test Script                   ║');
  console.log(`║  Target: ${BASE_URL.padEnd(36)}║`);
  console.log('╚══════════════════════════════════════════════╝');

  await resetDb();

  const results: TestResult[] = [];

  // ── Test 1: Bootstrap ──────────────────────────────────────────────────────
  let trustedKp: KeyPair | undefined;
  let trustedJar: CookieJar | undefined;
  try {
    const r = await testBootstrap();
    trustedKp  = r.kp;
    trustedJar = r.jar;
    results.push({ name: 'BOOTSTRAP', passed: true });
  } catch (err) {
    results.push({ name: 'BOOTSTRAP', passed: false, error: String(err) });
    console.error('  ✗ BOOTSTRAP failed:', err);
  }

  // ── Test 2: Trusted Device ─────────────────────────────────────────────────
  if (trustedKp && trustedJar) {
    try {
      await testTrustedDevice(trustedKp, trustedJar);
      results.push({ name: 'TRUSTED_DEVICE', passed: true });
    } catch (err) {
      results.push({ name: 'TRUSTED_DEVICE', passed: false, error: String(err) });
      console.error('  ✗ TRUSTED_DEVICE failed:', err);
    }

    // ── Test 3: New Device + Approval ────────────────────────────────────────
    try {
      await testNewDeviceApproval(trustedKp, trustedJar);
      results.push({ name: 'NEW_DEVICE+APPROVAL', passed: true });
    } catch (err) {
      results.push({ name: 'NEW_DEVICE+APPROVAL', passed: false, error: String(err) });
      console.error('  ✗ NEW_DEVICE+APPROVAL failed:', err);
    }

    // ── Test 4: Blocked ──────────────────────────────────────────────────────
    try {
      await testBlocked(trustedKp, trustedJar);
      results.push({ name: 'BLOCKED', passed: true });
    } catch (err) {
      results.push({ name: 'BLOCKED', passed: false, error: String(err) });
      console.error('  ✗ BLOCKED failed:', err);
    }
  } else {
    results.push({ name: 'TRUSTED_DEVICE',    passed: false, error: 'skipped (Bootstrap failed)' });
    results.push({ name: 'NEW_DEVICE+APPROVAL', passed: false, error: 'skipped (Bootstrap failed)' });
    results.push({ name: 'BLOCKED',            passed: false, error: 'skipped (Bootstrap failed)' });
  }

  // ── Test 5: Eval endpoints ────────────────────────────────────────────────
  try {
    await testEvalEndpoints();
    results.push({ name: 'EVAL_ENDPOINTS', passed: true });
  } catch (err) {
    results.push({ name: 'EVAL_ENDPOINTS', passed: false, error: String(err) });
    console.error('  ✗ EVAL_ENDPOINTS failed:', err);
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('\n╔══════════════════════════════════════════════╗');
  console.log('║  RESULTS                                     ║');
  console.log('╠══════════════════════════════════════════════╣');
  let passed = 0;
  for (const r of results) {
    const icon  = r.passed ? '✓' : '✗';
    const label = r.name.padEnd(24);
    const note  = r.passed ? 'PASS' : `FAIL${r.error ? ` — ${r.error.slice(0, 40)}` : ''}`;
    console.log(`║  ${icon} ${label} ${note}`);
    if (r.passed) passed++;
  }
  console.log('╠══════════════════════════════════════════════╣');
  console.log(`║  ${passed}/${results.length} tests passed${' '.repeat(34 - String(passed).length - String(results.length).length)}║`);
  console.log('╚══════════════════════════════════════════════╝');

  process.exit(passed === results.length ? 0 : 1);
}

main().catch(err => {
  console.error('[fatal]', err);
  process.exit(1);
});
