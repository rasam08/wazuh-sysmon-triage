import path from 'node:path';
import { createRunExecutor } from './run-executor';
import { RunIndexService } from './run-index-service';
import { RunQueueService } from './run-queue-service';
import { createRunner, type Runner } from './runner';
import {
  resolveDefaultOutDir,
  resolveOfflineInputRoots,
  type RouteContext,
  type RouteOptions,
} from './routes-common';

const runQueueServices = new Map<string, RunQueueService>();
const runIndexServices = new Map<string, RunIndexService>();

function getOrCreateRunQueueService(outDir: string, runner: Runner): RunQueueService {
  const key = path.resolve(outDir).toLowerCase();
  const executor = createRunExecutor(runner);
  const existing = runQueueServices.get(key);
  if (existing) {
    existing.setExecutor(executor);
    return existing;
  }
  const created = new RunQueueService({ outDir, executor });
  runQueueServices.set(key, created);
  return created;
}

function getOrCreateRunIndexService(outDir: string): RunIndexService {
  const key = path.resolve(outDir).toLowerCase();
  const existing = runIndexServices.get(key);
  if (existing) {
    return existing;
  }
  const created = new RunIndexService(outDir);
  runIndexServices.set(key, created);
  return created;
}

export function resolveContext(options: RouteOptions = {}): RouteContext {
  const rootDir = options.rootDir ? path.resolve(options.rootDir) : path.resolve(__dirname, '..', '..', '..');
  const outDir = options.outDir ? path.resolve(options.outDir) : resolveDefaultOutDir(rootDir);
  const offlineInputRoots = resolveOfflineInputRoots(rootDir, options);
  const runner = options.runner ?? createRunner({ rootDir });
  const runQueueService = options.runQueueService ?? getOrCreateRunQueueService(outDir, runner);
  const runIndexService = options.runIndexService ?? getOrCreateRunIndexService(outDir);
  if (!options.runQueueService) {
    runQueueService.setExecutor(createRunExecutor(runner));
  }
  return { rootDir, outDir, offlineInputRoots, runner, runQueueService, runIndexService };
}
