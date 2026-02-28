import { describe, expect, it } from 'vitest';
import { buildAttackNavigatorLayer } from '@/utils/exports';
import type { Case } from '@/types';

function makeCase(): Case {
  return {
    case_id: 'CASE-ATTACK-001',
    run_id: 'CASE-ATTACK-001',
    time_range: { start: '2026-02-27T00:00:00Z', end: '2026-02-27T01:00:00Z' },
    profile: 'soc',
    mode: 'offline',
    schema_version: '1.1.0',
    stats: {
      total_events: 10,
      by_event_id: { '1': 10 },
      alerts_generated: 2,
      alerts_suppressed: 0,
      suppression_hits: {},
      dropped_events: 0,
      dropped_by_reason: {},
      queues: { soc_malware: 2 },
      categories: { malware_execution: 2 },
      confidence_distribution: { high: 2 },
      network_connections: 0,
      suspicious_destinations: 0,
    },
    alerts: [
      {
        alert_id: 'A1',
        utc_time: '2026-02-27T00:10:00Z',
        score: 90,
        alert_type: 'powershell_obfuscation',
        category: 'malware_execution',
        queue: 'soc_malware',
        confidence: 'high',
        reason: 'r1',
        routing_why: 'rw1',
        image: 'powershell.exe',
        command_line: 'powershell',
        parent_image: 'explorer.exe',
        destination_ip: '',
        destination_port: null,
        process_guid: '{1}',
        tags: ['attack.t1059.001', 'source:test'],
      },
      {
        alert_id: 'A2',
        utc_time: '2026-02-27T00:11:00Z',
        score: 70,
        alert_type: 'suspicious_script',
        category: 'policy_violation',
        queue: 'soc_policy',
        confidence: 'medium',
        reason: 'r2',
        routing_why: 'rw2',
        image: 'cmd.exe',
        command_line: 'cmd /c',
        parent_image: 'explorer.exe',
        destination_ip: '',
        destination_port: null,
        process_guid: '{2}',
        tags: ['ATTACK.T1059.001'],
      },
    ],
    timeline: [],
    process_tree: {
      schema_version: '1.1.0',
      agent: { name: 'a', id: '1' },
      time_range: { start: '2026-02-27T00:00:00Z', end: '2026-02-27T01:00:00Z' },
      nodes: [],
      edges: [],
      artifacts: [],
    },
    report_md: '',
    query: {
      index: 'wazuh-alerts-*',
      start: '2026-02-27T00:00:00Z',
      end: '2026-02-27T01:00:00Z',
      event_ids: [1],
      size: 1000,
    },
    artifacts: [],
  };
}

describe('buildAttackNavigatorLayer', () => {
  it('generates ATT&CK navigator layer with merged techniques', () => {
    const layer = buildAttackNavigatorLayer(makeCase());
    const techniques = (layer.techniques ?? []) as Array<Record<string, unknown>>;
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.version).toBe('4.5');
    expect(techniques.length).toBe(1);
    expect(techniques[0].techniqueID).toBe('T1059.001');
    expect(techniques[0].score).toBe(80);
  });
});
