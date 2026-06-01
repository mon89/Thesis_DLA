/**
 * Compute the Android apk-key-hash origin string from a SHA-256 cert fingerprint.
 *
 * Usage:
 *   npx ts-node scripts/compute-android-hash.ts "14:6D:E9:83:C5:73:06:50:D8:EE:..."
 *
 * Output:
 *   Base64url hash : abc123...
 *   ANDROID_ORIGIN : android:apk-key-hash:abc123...
 */

const fingerprint = process.argv[2];

if (!fingerprint) {
  console.error('Usage: npx ts-node scripts/compute-android-hash.ts "AA:BB:CC:..."');
  process.exit(1);
}

// Remove colons, decode hex bytes, base64url encode
const hex    = fingerprint.replace(/:/g, '');
const bytes  = Buffer.from(hex, 'hex');
const b64url = bytes.toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');

console.log(`Base64url hash : ${b64url}`);
console.log(`ANDROID_ORIGIN : android:apk-key-hash:${b64url}`);
