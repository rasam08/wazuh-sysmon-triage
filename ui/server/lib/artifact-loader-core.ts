import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  buildBundleFromRaw,
  looksLikeCaseDir,
  parseAlerts,
  parseCsvRows,
  safeText,
  toCase,
  toFailedRun,
  toRun,
} from './artifact-loader-mappers';
import {
  ArtifactError,
  type ApiAlert,
  type ApiAlertBundle,
  type ApiCase,
  type ApiRun,
  type CaseArtifacts,
} from './artifact-loader-types';
import { validateCaseId } from './validators';

export { ArtifactError };
export type { ApiRun };

const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_CSV_BYTES = 8 * 1024 * 1024;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const MAX_BUNDLE_FILES = 5000;

function resolveRealDirOrResolved(dirPath: string): string {
  const resolved = path.resolve(dirPath);
  if (!fs.existsSync(resolved)) return resolved;
  return fs.realpathSync(resolved);
}

function assertInsideBase(baseDir: string, targetPath: string): void {
  const relative = path.relative(baseDir, targetPath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new ArtifactError('Requested path is outside allowed output directory', 404);
  }
}

function resolveCaseDir(outDir: string, caseId: string, mustExist = true): string {
  const safeCaseId = validateCaseId(caseId);
  const realOutDir = resolveRealDirOrResolved(outDir);
  const candidate = path.resolve(realOutDir, safeCaseId);
  if (!fs.existsSync(candidate)) {
    if (mustExist) {
      throw new ArtifactError(`Case ${safeCaseId} not found`, 404);
    }
    assertInsideBase(realOutDir, candidate);
    return candidate;
  }
  const realCandidate = fs.realpathSync(candidate);
  assertInsideBase(realOutDir, realCandidate);
  return realCandidate;
}

async function readTextFile(filePath: string, maxBytes: number): Promise<string> {
  if (!fs.existsSync(filePath)) return '';
  const stat = await fsp.stat(filePath);
  if (stat.size > maxBytes) {
    throw new ArtifactError(`File too large: ${path.basename(filePath)}`, 413);
  }
  return fsp.readFile(filePath, 'utf-8');
}

async function readJsonFile<T = Record<string, unknown>>(filePath: string): Promise<T | null> {
  if (!fs.existsSync(filePath)) return null;
  const raw = await readTextFile(filePath, MAX_JSON_BYTES);
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new ArtifactError(`Invalid JSON in ${path.basename(filePath)}`);
  }
}

async function readCaseArtifacts(caseDir: string): Promise<CaseArtifacts> {
  const caseId = path.basename(caseDir);
  const [metadata, statsRaw, queryRaw, reportMd, processTreeRaw, timelineCsv, alertsCsv] = await Promise.all([
    readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'run_metadata.json')),
    readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'stats.json')),
    readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'query.json')),
    readTextFile(path.resolve(caseDir, 'report.md'), MAX_REPORT_BYTES),
    readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'process_tree.json')),
    readTextFile(path.resolve(caseDir, 'timeline.csv'), MAX_CSV_BYTES),
    readTextFile(path.resolve(caseDir, 'alerts.csv'), MAX_CSV_BYTES),
  ]);
  const timelineRawRows = parseCsvRows(timelineCsv);
  const alertRows = parseCsvRows(alertsCsv);

  const entries = await fsp.readdir(caseDir, { withFileTypes: true });
  const bundleFiles = entries
    .filter((entry) => entry.isFile() && /^alert_.+_bundle\.json$/i.test(entry.name))
    .slice(0, MAX_BUNDLE_FILES)
    .map((entry) => path.resolve(caseDir, entry.name));

  const bundlesById = new Map<string, ApiAlertBundle>();
  const bundleResults = await Promise.all(
    bundleFiles.map(async (filePath) => {
      const raw = await readJsonFile<Record<string, unknown>>(filePath);
      if (!raw) return null;
      const fromName = safeText(path.basename(filePath).match(/^alert_(.+)_bundle\.json$/i)?.[1] || '').trim();
      return buildBundleFromRaw(raw, fromName);
    }),
  );
  for (const bundle of bundleResults) {
    if (!bundle) continue;
    bundlesById.set(bundle.alert.alert_id, bundle);
  }

  const alerts = parseAlerts(alertRows, bundlesById);
  for (const alert of alerts) {
    const bundle = bundlesById.get(alert.alert_id);
    if (!bundle) continue;
    bundle.alert = { ...bundle.alert, ...alert };
  }

  return {
    dir: caseDir,
    caseId,
    metadata,
    statsRaw,
    queryRaw,
    reportMd,
    processTreeRaw,
    timelineRawRows,
    alerts,
    bundlesById,
  };
}

async function listCaseIds(outDir: string): Promise<string[]> {
  const resolvedOutDir = resolveRealDirOrResolved(outDir);
  if (!fs.existsSync(resolvedOutDir)) return [];
  const entries = await fsp.readdir(resolvedOutDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

async function loadCaseArtifacts(outDir: string, caseId: string): Promise<CaseArtifacts> {
  const caseDir = resolveCaseDir(outDir, caseId, true);
  return readCaseArtifacts(caseDir);
}

export async function loadAllRuns(outDir: string): Promise<ApiRun[]> {
  const resolvedOutDir = resolveRealDirOrResolved(outDir);
  const caseIds = await listCaseIds(outDir);
  const runs = (
    await Promise.all(
      caseIds.map(async (caseId): Promise<ApiRun | null> => {
        try {
          const caseDir = path.resolve(resolvedOutDir, caseId);
          const [metadata, statsRaw] = await Promise.all([
            readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'run_metadata.json')),
            readJsonFile<Record<string, unknown>>(path.resolve(caseDir, 'stats.json')),
          ]);
          if (!metadata) return null;
          return toRun({
            dir: caseDir,
            caseId,
            metadata,
            statsRaw,
            queryRaw: null,
            reportMd: '',
            processTreeRaw: null,
            timelineRawRows: [],
            alerts: [],
            bundlesById: new Map<string, ApiAlertBundle>(),
          });
        } catch (error) {
          const caseDir = path.resolve(resolvedOutDir, caseId);
          if (!looksLikeCaseDir(caseDir)) return null;
          return toFailedRun(outDir, caseId, error);
        }
      }),
    )
  ).filter((run): run is ApiRun => run !== null);
  runs.sort((a, b) => {
    const left = new Date(b.completed_at || b.started_at).getTime();
    const right = new Date(a.completed_at || a.started_at).getTime();
    return left - right;
  });
  return runs;
}

export async function loadRun(outDir: string, caseId: string): Promise<ApiRun> {
  const artifacts = await loadCaseArtifacts(outDir, caseId);
  return toRun(artifacts);
}

export async function loadCase(outDir: string, caseId: string): Promise<ApiCase> {
  const artifacts = await loadCaseArtifacts(outDir, caseId);
  return toCase(artifacts);
}

export async function deleteCase(outDir: string, caseId: string): Promise<void> {
  const caseDir = resolveCaseDir(outDir, caseId, true);
  try {
    await fsp.rm(caseDir, { recursive: true, force: false, maxRetries: 2 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new ArtifactError(`Case ${caseId} not found`, 404);
    }
    throw new ArtifactError(`Failed to delete case ${caseId}`);
  }
}

export async function loadAlerts(outDir: string, caseId: string): Promise<ApiAlert[]> {
  const artifacts = await loadCaseArtifacts(outDir, caseId);
  return artifacts.alerts;
}

export async function loadAlertBundle(outDir: string, caseId: string, alertId: string): Promise<ApiAlertBundle> {
  const artifacts = await loadCaseArtifacts(outDir, caseId);
  const normalizedAlertId = safeText(alertId).trim();
  const bundle = artifacts.bundlesById.get(normalizedAlertId);
  if (!bundle) {
    throw new ArtifactError(`Bundle ${normalizedAlertId} not found in case ${caseId}`, 404);
  }
  return bundle;
}

export async function loadReport(outDir: string, caseId: string): Promise<string> {
  const artifacts = await loadCaseArtifacts(outDir, caseId);
  return artifacts.reportMd;
}
