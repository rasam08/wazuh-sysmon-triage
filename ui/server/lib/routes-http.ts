import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import { ValidationError } from './validators';

const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024; // 1 MB

export function parseRequestBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on('data', (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > MAX_REQUEST_BODY_BYTES) {
        req.destroy();
        reject(new ValidationError('Request body too large', 413));
        return;
      }
      chunks.push(buf);
    });
    req.on('error', reject);
    req.on('end', () => {
      if (!chunks.length) {
        resolve(null);
        return;
      }
      const raw = Buffer.concat(chunks).toString('utf-8');
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new ValidationError('Invalid JSON request body'));
      }
    });
  });
}

function isMutatingMethod(method: string): boolean {
  return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
}

export function getHeaderValue(headers: IncomingHttpHeaders | undefined, name: string): string | null {
  if (!headers) return null;
  const raw = headers[name.toLowerCase()];
  if (Array.isArray(raw)) return raw[0] ?? null;
  return typeof raw === 'string' ? raw : null;
}

function resolveRequestProtocol(req: IncomingMessage): 'http' | 'https' {
  const forwardedProto = getHeaderValue(req.headers, 'x-forwarded-proto');
  if (forwardedProto) {
    const normalized = forwardedProto.split(',')[0]?.trim().toLowerCase();
    if (normalized === 'https' || normalized === 'http') {
      return normalized;
    }
  }
  return (req.socket as { encrypted?: boolean } | undefined)?.encrypted ? 'https' : 'http';
}

export function enforceCsrfGuard(req: IncomingMessage, method: string): void {
  if (!isMutatingMethod(method)) return;
  const origin = getHeaderValue(req.headers, 'origin');
  const secFetchSite = getHeaderValue(req.headers, 'sec-fetch-site');
  const browserRequest = Boolean(origin) || Boolean(secFetchSite);
  if (!browserRequest) return;

  const requestedWith = getHeaderValue(req.headers, 'x-requested-with');
  if (!requestedWith || requestedWith.toLowerCase() !== 'xmlhttprequest') {
    throw new ValidationError('Missing or invalid X-Requested-With header', 403);
  }

  if (secFetchSite) {
    const normalizedSite = secFetchSite.trim().toLowerCase();
    if (!['same-origin', 'same-site', 'none'].includes(normalizedSite)) {
      throw new ValidationError('Cross-site request rejected by CSRF policy', 403);
    }
  }

  if (!origin) return;

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    throw new ValidationError('Invalid Origin header', 403);
  }
  const host = getHeaderValue(req.headers, 'host');
  if (!host) {
    throw new ValidationError('Missing Host header for same-origin validation', 403);
  }
  if (parsedOrigin.host.toLowerCase() !== host.trim().toLowerCase()) {
    throw new ValidationError('Cross-origin request rejected by CSRF policy', 403);
  }
  const expectedProtocol = resolveRequestProtocol(req);
  if (parsedOrigin.protocol !== `${expectedProtocol}:`) {
    throw new ValidationError('Origin protocol mismatch rejected by CSRF policy', 403);
  }
}

function setSecurityHeaders(res: ServerResponse): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

export function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.statusCode = status;
  setSecurityHeaders(res);
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(payload));
}

export function sendText(
  res: ServerResponse,
  status: number,
  payload: string,
  contentType = 'text/plain; version=0.0.4',
): void {
  res.statusCode = status;
  setSecurityHeaders(res);
  res.setHeader('Content-Type', contentType);
  res.end(payload);
}

export function applySseHeaders(res: ServerResponse): void {
  setSecurityHeaders(res);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
}
