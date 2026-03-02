// @vitest-environment node
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { dispatchApiRequest } from '../../server/lib/routes';

function writeJson(filePath: string, payload: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload), 'utf-8');
}

function writeText(filePath: string, payload: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, payload, 'utf-8');
}

function createCaseFixture(outDir: string, caseId: string): void {
  const caseDir = path.resolve(outDir, caseId);
  fs.mkdirSync(caseDir, { recursive: true });
  writeJson(path.resolve(caseDir, 'run_metadata.json'), {
    schema_version: '1.1.0',
    run_id: caseId,
    case_id: caseId,
    profile: 'soc',
    start: '2026-02-01T00:00:00.000Z',
    end: '2026-02-01T00:05:00.000Z',
    total_duration_ms: 300000,
    counts: {
      normalized_events: 1,
      alerts: 1,
      suppressed_alerts: 0,
    },
  });
  writeJson(path.resolve(caseDir, 'stats.json'), {
    total_events: 1,
    events_by_type: { process_create: 1, network_connect: 0 },
    suppression_hits: {},
    truncation: { truncated: false, reason: null },
  });
  writeJson(path.resolve(caseDir, 'query.json'), {
    index: 'wazuh-alerts-*',
    size: 1000,
  });
  writeJson(path.resolve(caseDir, 'process_tree.json'), {
    schema_version: '1.1.0',
    agent: { name: 'perf-agent', id: '999' },
    time_range: { start: '2026-02-01T00:00:00.000Z', end: '2026-02-01T00:05:00.000Z' },
    nodes: [],
    edges: [],
    artifacts: [],
  });
  writeText(
    path.resolve(caseDir, 'alerts.csv'),
    [
      'utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags',
      '2026-02-01T00:00:00.000Z,90,powershell_obfuscation,malware_execution,soc_malware,high,test,routed,powershell.exe,powershell.exe -enc,explorer.exe,,,{GUID-1},attack.t1059',
    ].join('\n'),
  );
  writeText(
    path.resolve(caseDir, 'timeline.csv'),
    [
      'ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id',
      '2026-02-01T00:00:00.000Z,1,powershell.exe,powershell.exe -enc,explorer.exe,,HOST\\user,92203,perf-agent,999',
    ].join('\n'),
  );
  writeText(path.resolve(caseDir, 'report.md'), '# Perf fixture\n');
}

describe('server artifact loading performance', () => {
  it('handles large artifact directories within budget', async () => {
    const outDir = path.resolve(`ui/.tmp-server-perf-${Date.now()}`);
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.mkdirSync(outDir, { recursive: true });
    try {
      const caseCount = 200;
      for (let index = 0; index < caseCount; index += 1) {
        createCaseFixture(outDir, `CASE-PERF-${String(index).padStart(4, '0')}`);
      }

      const runsStartedAt = performance.now();
      const runsResponse = await dispatchApiRequest({ method: 'GET', url: '/api/runs' }, { outDir });
      const runsElapsedMs = performance.now() - runsStartedAt;
      expect(runsResponse).not.toBeNull();
      expect(runsResponse?.status).toBe(200);
      expect(runsElapsedMs).toBeLessThan(4000);
      const manifestPath = path.resolve(outDir, '.run-index', 'run_manifest.json');
      expect(fs.existsSync(manifestPath)).toBe(true);

      const caseStartedAt = performance.now();
      const caseResponse = await dispatchApiRequest(
        { method: 'GET', url: '/api/cases/CASE-PERF-0199' },
        { outDir },
      );
      const caseElapsedMs = performance.now() - caseStartedAt;
      expect(caseResponse).not.toBeNull();
      expect(caseResponse?.status).toBe(200);
      expect(caseElapsedMs).toBeLessThan(1200);
    } finally {
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  }, 15000);
});
