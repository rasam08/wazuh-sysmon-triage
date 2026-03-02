import { createHash } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { ApiDispatchResponse } from './routes-common';
import { getHeaderValue } from './routes-http';
import { ValidationError } from './validators';

interface IdempotencyRecord {
  requestHash: string;
  response: ApiDispatchResponse;
  createdAtMs: number;
}

const idempotencyRecords = new Map<string, IdempotencyRecord>();
const MAX_IDEMPOTENCY_KEY_LENGTH = 128;

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function hashPayload(value: unknown): string {
  return createHash('sha256').update(stableStringify(value ?? null)).digest('hex');
}

export function cloneResponse(response: ApiDispatchResponse): ApiDispatchResponse {
  return {
    status: response.status,
    body: JSON.parse(JSON.stringify(response.body)) as unknown,
  };
}

export function parseIdempotencyKey(headers: IncomingHttpHeaders | undefined): string | null {
  const raw = getHeaderValue(headers, 'idempotency-key');
  if (raw === null) return null;
  const key = raw.trim();
  if (!key) {
    throw new ValidationError('Idempotency-Key cannot be empty');
  }
  if (key.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
    throw new ValidationError(`Idempotency-Key exceeds ${MAX_IDEMPOTENCY_KEY_LENGTH} characters`);
  }
  return key;
}

export function pruneIdempotencyRecords(nowMs: number, windowMs: number): void {
  for (const [key, record] of idempotencyRecords.entries()) {
    if (nowMs - record.createdAtMs >= windowMs) {
      idempotencyRecords.delete(key);
    }
  }
}

export function getIdempotencyRecord(idempotencyKey: string): IdempotencyRecord | undefined {
  return idempotencyRecords.get(idempotencyKey);
}

export function setIdempotencyRecord(
  idempotencyKey: string,
  record: IdempotencyRecord,
): void {
  idempotencyRecords.set(idempotencyKey, record);
}
