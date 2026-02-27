// TOTP (Time-based One-Time Password) — RFC 6238
// Uses Web Crypto HMAC-SHA1 with song hash as secret

const TOTP_PERIOD = 30; // seconds
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // ±1 period tolerance

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function hmacSha1(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, message as BufferSource);
  return new Uint8Array(sig);
}

function intToBytes(num: number): Uint8Array {
  const bytes = new Uint8Array(8);
  // Big-endian 64-bit integer
  for (let i = 7; i >= 0; i--) {
    bytes[i] = num & 0xff;
    num = Math.floor(num / 256);
  }
  return bytes;
}

function dynamicTruncate(hmac: Uint8Array): number {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return code % Math.pow(10, TOTP_DIGITS);
}

export async function generateTOTP(songHashB64: string, timeOverride?: number): Promise<string> {
  const secret = base64ToBytes(songHashB64);
  const time = timeOverride ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / TOTP_PERIOD);
  const counterBytes = intToBytes(counter);
  const hmac = await hmacSha1(secret, counterBytes);
  const code = dynamicTruncate(hmac);
  return code.toString().padStart(TOTP_DIGITS, '0');
}

export async function verifyTOTP(songHashB64: string, userCode: string): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const time = now + i * TOTP_PERIOD;
    const expected = await generateTOTP(songHashB64, time);
    if (expected === userCode.padStart(TOTP_DIGITS, '0')) {
      return true;
    }
  }
  return false;
}

export function getTimeRemaining(): number {
  return TOTP_PERIOD - (Math.floor(Date.now() / 1000) % TOTP_PERIOD);
}

export { TOTP_PERIOD, TOTP_DIGITS };
