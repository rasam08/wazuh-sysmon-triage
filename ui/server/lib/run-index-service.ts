import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { ApiRun } from './artifact-loader';

interface RunIndexManifest {
  version: 1;
  generated_at_ms: number;
  runs: ApiRun[];
}

const RUN_INDEX_DIR = '.run-index';
const RUN_INDEX_FILENAME = 'run_manifest.json';
const DEFAULT_RUN_INDEX_TTL_MS = 5000;

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && Number.isInteger(parsed) && parsed > 0) {
    return parsed;
  }
  return fallback;
}

function cloneRuns(runs: ApiRun[]): ApiRun[] {
  return JSON.parse(JSON.stringify(runs)) as ApiRun[];
}

async function writeJsonAtomic(filePath: string, payload: unknown): Promise<void> {
  const directory = path.dirname(filePath);
  await fsp.mkdir(directory, { recursive: true });
  const tmpPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  await fsp.writeFile(tmpPath, JSON.stringify(payload, null, 2), 'utf-8');
  try {
    await fsp.rename(tmpPath, filePath);
    return;
  } catch {
    // Fallback for filesystems that temporarily lock rename destinations.
    await fsp.copyFile(tmpPath, filePath);
    await fsp.rm(tmpPath, { force: true });
  }
}

export class RunIndexService {
  private readonly outDir: string;

  private readonly manifestPath: string;

  private readonly ttlMs: number;

  private inMemory: RunIndexManifest | null = null;

  constructor(outDir: string, ttlMs = parsePositiveInt(process.env.TRIAGE_RUN_INDEX_TTL_MS, DEFAULT_RUN_INDEX_TTL_MS)) {
    this.outDir = path.resolve(outDir);
    this.manifestPath = path.resolve(this.outDir, RUN_INDEX_DIR, RUN_INDEX_FILENAME);
    this.ttlMs = ttlMs;
  }

  invalidate(): void {
    this.inMemory = null;
    void fsp.rm(this.manifestPath, { force: true });
  }

  async listRuns(loader: () => Promise<ApiRun[]>): Promise<ApiRun[]> {
    const nowMs = Date.now();
    const memory = this.inMemory;
    if (memory && nowMs - memory.generated_at_ms <= this.ttlMs) {
      return cloneRuns(memory.runs);
    }

    const diskManifest = await this.loadManifest();
    if (diskManifest && nowMs - diskManifest.generated_at_ms <= this.ttlMs) {
      this.inMemory = diskManifest;
      return cloneRuns(diskManifest.runs);
    }

    const runs = await loader();
    const manifest: RunIndexManifest = {
      version: 1,
      generated_at_ms: nowMs,
      runs,
    };
    this.inMemory = manifest;
    try {
      await writeJsonAtomic(this.manifestPath, manifest);
    } catch {
      // Best effort persistence; keep in-memory cache even if disk write fails.
    }
    return cloneRuns(runs);
  }

  private async loadManifest(): Promise<RunIndexManifest | null> {
    if (!fs.existsSync(this.manifestPath)) {
      return null;
    }
    try {
      const raw = await fsp.readFile(this.manifestPath, 'utf-8');
      const parsed = JSON.parse(raw) as RunIndexManifest;
      if (
        !parsed
        || parsed.version !== 1
        || !Array.isArray(parsed.runs)
        || typeof parsed.generated_at_ms !== 'number'
      ) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }
}
