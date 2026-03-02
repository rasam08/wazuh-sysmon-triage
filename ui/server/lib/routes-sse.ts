import type { IncomingMessage, ServerResponse } from 'node:http';
import { writeSseEvent } from './routes-common';
import { applySseHeaders } from './routes-http';
import type { RunQueueService } from './run-queue-service';

interface StreamOptions {
  req: IncomingMessage;
  res: ServerResponse;
  runQueueService: RunQueueService;
  jobId: string;
  onStatusLogged: (status: number) => void;
}

export function startJobProgressStream(options: StreamOptions): void {
  const { req, res, runQueueService, jobId, onStatusLogged } = options;
  const job = runQueueService.getJob(jobId);
  let logged = false;
  const logOnce = (status: number): void => {
    if (logged) return;
    logged = true;
    onStatusLogged(status);
  };

  res.statusCode = 200;
  applySseHeaders(res);
  const flushable = res as ServerResponse & { flushHeaders?: () => void };
  if (typeof flushable.flushHeaders === 'function') {
    flushable.flushHeaders();
  }

  const sendSnapshot = (event: 'progress' | 'terminal' | 'heartbeat', payload: unknown) => {
    writeSseEvent(res, event, payload);
  };

  sendSnapshot('progress', {
    event: 'progress',
    job_id: job.job_id,
    case_id: job.case_id,
    stage: job.stage,
    progress_pct: job.progress_pct,
    status: job.status,
    ts: new Date().toISOString(),
    ...(job.message ? { message: job.message } : {}),
    ...(job.cancel_reason ? { cancel_reason: job.cancel_reason } : {}),
  });

  const unsubscribe = runQueueService.subscribe(jobId, (event) => {
    sendSnapshot(event.event, event);
    if (event.event === 'terminal') {
      unsubscribe();
      if (!res.writableEnded) {
        res.end();
      }
      logOnce(200);
    }
  });

  req.on('close', () => {
    unsubscribe();
    if (!res.writableEnded) {
      res.end();
    }
    logOnce(200);
  });
}
