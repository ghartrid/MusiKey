// Zero-Knowledge Proof — Commit-Reveal Scheme
// Proves knowledge of song without transmitting song data

import { ZKPCommitmentData } from './types';

function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

// Create commitment: H(songData || nonce)
export async function createCommitment(songHash: ArrayBuffer): Promise<ZKPCommitmentData> {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);

  const combined = new Uint8Array(new Uint8Array(songHash).length + nonce.length);
  combined.set(new Uint8Array(songHash));
  combined.set(nonce, new Uint8Array(songHash).length);

  const commitment = await crypto.subtle.digest('SHA-256', combined);

  return {
    commitment: arrayBufferToHex(commitment),
    nonce: arrayBufferToHex(nonce.buffer),
  };
}

// Create a challenge (random 32 bytes)
export function createChallenge(): string {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  return arrayBufferToHex(challenge.buffer);
}

// Create proof: H(songData || challenge)
export async function createProof(songHash: ArrayBuffer, challenge: string): Promise<string> {
  const challengeBytes = new Uint8Array(hexToArrayBuffer(challenge));
  const combined = new Uint8Array(new Uint8Array(songHash).length + challengeBytes.length);
  combined.set(new Uint8Array(songHash));
  combined.set(challengeBytes, new Uint8Array(songHash).length);

  const proof = await crypto.subtle.digest('SHA-256', combined);
  return arrayBufferToHex(proof);
}

// Verify: recompute proof from known songHash + challenge and compare
export async function verifyProof(
  songHash: ArrayBuffer,
  challenge: string,
  proof: string
): Promise<boolean> {
  const expected = await createProof(songHash, challenge);
  // Constant-time comparison
  if (expected.length !== proof.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ proof.charCodeAt(i);
  }
  return diff === 0;
}

// Verify commitment matches songHash + nonce
export async function verifyCommitment(
  songHash: ArrayBuffer,
  commitmentData: ZKPCommitmentData
): Promise<boolean> {
  const nonce = new Uint8Array(hexToArrayBuffer(commitmentData.nonce));
  const combined = new Uint8Array(new Uint8Array(songHash).length + nonce.length);
  combined.set(new Uint8Array(songHash));
  combined.set(nonce, new Uint8Array(songHash).length);

  const computed = await crypto.subtle.digest('SHA-256', combined);
  const computedHex = arrayBufferToHex(computed);

  // Constant-time comparison
  if (computedHex.length !== commitmentData.commitment.length) return false;
  let diff = 0;
  for (let i = 0; i < computedHex.length; i++) {
    diff |= computedHex.charCodeAt(i) ^ commitmentData.commitment.charCodeAt(i);
  }
  return diff === 0;
}
