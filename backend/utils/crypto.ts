import crypto from 'crypto';

/**
 * Produces a stable SHA-256 hex fingerprint of a JWK public key.
 * Keys are sorted alphabetically before hashing so that key-insertion
 * order differences don't produce different device IDs.
 */
export function computeDeviceId(dbkPublicKeyJwk: object): string {
  const sorted = sortObjectKeys(dbkPublicKeyJwk);
  const canonical = JSON.stringify(sorted);
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

/**
 * Returns 32 cryptographically random bytes encoded as base64url.
 * Used as the DBK challenge sent to the iOS client.
 */
export function generateDbkChallenge(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Verifies an ECDSA-SHA256 signature produced by iOS Secure Enclave.
 *
 * iOS returns raw r||s format (IEEE P-1363), NOT DER-encoded ASN.1.
 * Node's crypto.verify() needs dsaEncoding:'ieee-p1363' to handle this.
 *
 * @param dbkPublicKeyJwk  - JWK object containing the EC public key
 * @param challenge        - base64url-encoded challenge that was signed
 * @param signatureB64     - base64url-encoded raw signature (r||s, 64 bytes for P-256)
 * @returns true if the signature is valid, false otherwise
 */
export function verifyDbkSignature(
  dbkPublicKeyJwk: object,
  challenge: string,
  signatureB64: string,
): boolean {
  try {
    const key = crypto.createPublicKey({ key: dbkPublicKeyJwk as JsonWebKey, format: 'jwk' });
    const challengeBuf = Buffer.from(challenge, 'base64url');
    const sigBuf       = Buffer.from(signatureB64, 'base64url');

    return crypto.verify(
      'sha256',
      challengeBuf,
      { key, dsaEncoding: 'ieee-p1363' },
      sigBuf,
    );
  } catch {
    return false;
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function sortObjectKeys(obj: unknown): unknown {
  if (Array.isArray(obj))          return obj.map(sortObjectKeys);
  if (obj !== null && typeof obj === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[k] = sortObjectKeys((obj as Record<string, unknown>)[k]);
    }
    return sorted;
  }
  return obj;
}
