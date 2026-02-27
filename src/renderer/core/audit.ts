// Audit Log — Cryptographically chained event log for MusiKey credentials
// Each entry includes SHA-256 hash of previous entry, forming a tamper-evident chain

import {
  AuditAction,
  AuditLogEntry,
  AuditChainResult,
  AuditSummary,
} from './webauthn-types';
import { MusikeyCredential } from './types';

const MAX_ENTRIES = 1000;

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  return arrayBufferToBase64(hash);
}

export async function createAuditEntry(
  action: AuditAction,
  rpId: string,
  credentialId: string,
  userId: string,
  signCount?: number,
  detail?: string,
  prevEntries?: AuditLogEntry[]
): Promise<AuditLogEntry> {
  const timestamp = Date.now();

  // Chain hash: SHA-256 of previous entry's entryHash, or 'genesis'
  let prevHash = 'genesis';
  if (prevEntries && prevEntries.length > 0) {
    prevHash = prevEntries[prevEntries.length - 1].entryHash;
  }

  // Compute entry hash over all fields (excluding entryHash itself)
  const content = JSON.stringify({
    timestamp,
    action,
    rpId,
    credentialId,
    userId,
    signCount,
    detail,
    prevHash,
  });
  const entryHash = await sha256Hex(content);

  return {
    timestamp,
    action,
    rpId,
    credentialId,
    userId,
    signCount,
    detail,
    prevHash,
    entryHash,
  };
}

export async function verifyAuditChain(entries: AuditLogEntry[]): Promise<AuditChainResult> {
  if (entries.length === 0) {
    return { valid: true };
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // Verify prevHash linkage
    if (i === 0) {
      if (entry.prevHash !== 'genesis') {
        return { valid: false, brokenAt: 0 };
      }
    } else {
      if (entry.prevHash !== entries[i - 1].entryHash) {
        return { valid: false, brokenAt: i };
      }
    }

    // Verify entryHash integrity
    const content = JSON.stringify({
      timestamp: entry.timestamp,
      action: entry.action,
      rpId: entry.rpId,
      credentialId: entry.credentialId,
      userId: entry.userId,
      signCount: entry.signCount,
      detail: entry.detail,
      prevHash: entry.prevHash,
    });
    const expectedHash = await sha256Hex(content);
    if (expectedHash !== entry.entryHash) {
      return { valid: false, brokenAt: i };
    }
  }

  return { valid: true };
}

export function appendAuditEntry(
  credential: MusikeyCredential,
  entry: AuditLogEntry
): void {
  if (!credential.auditLog) {
    credential.auditLog = [];
  }

  credential.auditLog.push(entry);

  // Cap at MAX_ENTRIES (FIFO)
  if (credential.auditLog.length > MAX_ENTRIES) {
    credential.auditLog = credential.auditLog.slice(-MAX_ENTRIES);
  }
}

export async function getAuditSummary(entries: AuditLogEntry[]): Promise<AuditSummary> {
  const chainResult = await verifyAuditChain(entries);

  let totalAuths = 0;
  let totalFailures = 0;
  let lastAuthTime: number | null = null;
  let registrationCount = 0;
  let cloneWarnings = 0;

  for (const entry of entries) {
    switch (entry.action) {
      case 'authentication':
        totalAuths++;
        lastAuthTime = entry.timestamp;
        break;
      case 'auth_failure':
        totalFailures++;
        break;
      case 'registration':
        registrationCount++;
        break;
      case 'counter_mismatch':
        cloneWarnings++;
        break;
    }
  }

  return {
    totalAuths,
    totalFailures,
    lastAuthTime,
    registrationCount,
    cloneWarnings,
    chainValid: chainResult.valid,
  };
}
