import { ArtifactError } from './artifact-loader';
import type { ApiDispatchResponse } from './routes-common';
import { RunnerError } from './runner';
import { ValidationError } from './validators';

export function toErrorResponse(error: unknown): ApiDispatchResponse {
  if (error instanceof URIError) {
    return { status: 400, body: { error: 'Invalid URL encoding' } };
  }
  if (error instanceof ValidationError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof RunnerError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof ArtifactError) {
    return { status: error.status, body: { error: error.message } };
  }
  if (error instanceof Error) {
    return { status: 500, body: { error: 'Internal server error' } };
  }
  return { status: 500, body: { error: 'Internal server error' } };
}
