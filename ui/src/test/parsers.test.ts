import { describe, it, expect } from 'vitest';
import { filterAlerts, sortAlerts, parseAlertsCsv, parseTimelineCsv, DEFAULT_FILTERS } from '../data/parsers';
import type { Alert, AlertFilters, AlertSort } from '../types';

const makeAlert = (overrides: Partial<Alert> = {}): Alert => ({
  alert_id: 'A0001',
  utc_time: '2026-02-23T08:00:00Z',
  score: 85,
  alert_type: 'sigma_composite',
  category: 'malware_execution',
  queue: 'soc_malware',
  confidence: 'high',
  reason: 'Encoded PowerShell with download cradle',
  routing_why: 'score>=80 -> soc_malware',
  image: 'C:\\Windows\\System32\\powershell.exe',
  command_line: 'powershell.exe -enc abc',
  parent_image: 'C:\\Windows\\explorer.exe',
  destination_ip: '8.8.8.8',
  destination_port: 443,
  process_guid: '{GUID-1}',
  tags: ['attack.t1059', 'suspicious.encoding'],
  ...overrides,
});

describe('filterAlerts', () => {
  const alerts: Alert[] = [
    makeAlert({ alert_id: 'A0001', score: 95, queue: 'soc_malware', confidence: 'high', category: 'malware_execution' }),
    makeAlert({ alert_id: 'A0002', score: 70, queue: 'soc_policy', confidence: 'medium', category: 'persistence' }),
    makeAlert({ alert_id: 'A0003', score: 40, queue: 'soc_dev', confidence: 'low', category: 'developer_tooling' }),
    makeAlert({ alert_id: 'A0004', score: 60, queue: 'soc_info', confidence: 'low', category: 'policy_violation' }),
  ];

  it('returns all alerts with default filters', () => {
    const result = filterAlerts(alerts, DEFAULT_FILTERS);
    expect(result).toHaveLength(4);
  });

  it('filters by queue', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, queues: ['soc_malware'] });
    expect(result).toHaveLength(1);
    expect(result[0].alert_id).toBe('A0001');
  });

  it('filters by multiple queues', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, queues: ['soc_malware', 'soc_policy'] });
    expect(result).toHaveLength(2);
  });

  it('filters by confidence', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, confidences: ['high'] });
    expect(result).toHaveLength(1);
  });

  it('filters by category', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, categories: ['persistence'] });
    expect(result).toHaveLength(1);
    expect(result[0].alert_id).toBe('A0002');
  });

  it('filters by score range', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, score_min: 60, score_max: 80 });
    expect(result).toHaveLength(2); // A0002 (70) and A0004 (60)
  });

  it('filters by search text', () => {
    const result = filterAlerts(alerts, { ...DEFAULT_FILTERS, search: 'powershell' });
    expect(result).toHaveLength(4); // all have powershell in image
  });

  it('filters by tags', () => {
    const taggedAlerts = [
      makeAlert({ alert_id: 'T1', tags: ['attack.t1059'] }),
      makeAlert({ alert_id: 'T2', tags: ['attack.t1053'] }),
    ];
    const result = filterAlerts(taggedAlerts, { ...DEFAULT_FILTERS, tags: ['attack.t1053'] });
    expect(result).toHaveLength(1);
    expect(result[0].alert_id).toBe('T2');
  });

  it('combines multiple filter dimensions', () => {
    const result = filterAlerts(alerts, {
      ...DEFAULT_FILTERS,
      queues: ['soc_malware', 'soc_policy'],
      score_min: 80,
    });
    expect(result).toHaveLength(1);
    expect(result[0].alert_id).toBe('A0001');
  });
});

describe('sortAlerts', () => {
  const alerts: Alert[] = [
    makeAlert({ alert_id: 'A1', score: 50, utc_time: '2026-02-23T08:00:00Z', confidence: 'low' }),
    makeAlert({ alert_id: 'A2', score: 90, utc_time: '2026-02-23T07:00:00Z', confidence: 'high' }),
    makeAlert({ alert_id: 'A3', score: 70, utc_time: '2026-02-23T09:00:00Z', confidence: 'medium' }),
  ];

  it('sorts by score descending', () => {
    const result = sortAlerts(alerts, { field: 'score', direction: 'desc' });
    expect(result.map((a) => a.alert_id)).toEqual(['A2', 'A3', 'A1']);
  });

  it('sorts by score ascending', () => {
    const result = sortAlerts(alerts, { field: 'score', direction: 'asc' });
    expect(result.map((a) => a.alert_id)).toEqual(['A1', 'A3', 'A2']);
  });

  it('sorts by time descending (newest first)', () => {
    const result = sortAlerts(alerts, { field: 'utc_time', direction: 'desc' });
    expect(result.map((a) => a.alert_id)).toEqual(['A3', 'A1', 'A2']);
  });

  it('sorts by confidence descending', () => {
    const result = sortAlerts(alerts, { field: 'confidence', direction: 'desc' });
    expect(result.map((a) => a.alert_id)).toEqual(['A2', 'A3', 'A1']);
  });
});

describe('parseAlertsCsv', () => {
  it('parses CSV string into alert objects', () => {
    const csv = `alert_id,utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags
A0001,2026-02-23T08:00:00Z,85,sigma_composite,malware_execution,soc_malware,high,test reason,test routing,powershell.exe,ps -enc,explorer.exe,8.8.8.8,443,{GUID},attack.t1059;suspicious.encoding`;
    const result = parseAlertsCsv(csv);
    expect(result).toHaveLength(1);
    expect(result[0].alert_id).toBe('A0001');
    expect(result[0].score).toBe(85);
    expect(result[0].category).toBe('malware_execution');
    expect(result[0].tags).toEqual(['attack.t1059', 'suspicious.encoding']);
  });

  it('returns empty array for missing data', () => {
    expect(parseAlertsCsv('')).toEqual([]);
    expect(parseAlertsCsv('header_only')).toEqual([]);
  });

  it('handles quoted commas, escaped quotes, and multiline fields', () => {
    const csv = `alert_id,utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags
A0002,2026-02-23T08:00:00Z,88,powershell_obfuscation,malware_execution,soc_malware,high,"reason with comma, escaped quote ""ok"", and newline
line 2","route with comma, kept","C:\\Tools\\payload,loader.exe","powershell.exe -enc ""abc,123""",explorer.exe,8.8.4.4,443,{GUID-2},attack.t1059;signal:obfuscation`;
    const result = parseAlertsCsv(csv);
    expect(result).toHaveLength(1);
    expect(result[0].reason).toContain('reason with comma');
    expect(result[0].reason).toContain('newline\nline 2');
    expect(result[0].routing_why).toBe('route with comma, kept');
    expect(result[0].image).toBe('C:\\Tools\\payload,loader.exe');
    expect(result[0].command_line).toBe('powershell.exe -enc "abc,123"');
    expect(result[0].destination_port).toBe(443);
    expect(result[0].tags).toEqual(['attack.t1059', 'signal:obfuscation']);
  });
});

describe('parseTimelineCsv', () => {
  it('handles quoted values with commas and embedded newlines', () => {
    const csv = `ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id
2026-02-23T08:00:00Z,1,powershell.exe,"line1
line2,with,comma",explorer.exe,,HOST\\user,92203,agent-1,001`;
    const rows = parseTimelineCsv(csv);
    expect(rows).toHaveLength(1);
    expect(rows[0].command_line).toBe('line1\nline2,with,comma');
  });
});
