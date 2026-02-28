/**
 * Scenario Gym data model and built-in scenario definitions.
 * Offline scenarios map to NDJSON files under samples/scenario_gym/.
 */

import type { RunMode, TimePreset } from '@/types';

/* Types */

export type ScenarioTier = 'A' | 'B';
export type ScenarioStatus = 'not_run' | 'running' | 'passed' | 'failed' | 'canceled';
export type ScenarioStage = 'fetch' | 'normalize' | 'correlate' | 'detect' | 'render';
export type ScenarioPassCriteria = 'expected_detections' | 'no_alerts' | 'recognized_alert_schema';

export interface ScenarioExpectation {
  alert_type: string;
  min_score: number;
  queue: string;
  confidence: string;
}

export interface ScenarioArtifact {
  label: string;
  filename: string;
}

export interface ScenarioLiveConfig {
  time_preset: TimePreset;
  start?: string;
  end?: string;
  agent_name?: string;
  agent_id?: string;
  verify_tls?: boolean;
}

export interface ScenarioDefinition {
  id: string;
  name: string;
  mode: RunMode;
  file?: string;
  description: string;
  tier: ScenarioTier;
  mitre: string[];
  event_ids: number[];
  expected_detections: ScenarioExpectation[];
  expected_artifacts: string[];
  what_we_simulate: string;
  telemetry_highlights: string[];
  pass_criteria?: ScenarioPassCriteria;
  min_alerts_emitted?: number;
  live?: ScenarioLiveConfig;
}

export interface ScenarioRunResult {
  scenario_id: string;
  status: ScenarioStatus;
  current_stage?: ScenarioStage;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  case_id?: string;
  alerts_emitted: number;
  passed: boolean | null;
  error?: string;
  outputs: ScenarioArtifact[];
  alerts_preview?: Array<{
    alert_id: string;
    score: number;
    alert_type: string;
    queue: string;
    confidence: string;
    reason: string;
  }>;
}

/* Built-in scenarios */

export const SCENARIOS: ScenarioDefinition[] = [
  {
    id: 'encoded-powershell',
    name: 'Encoded PowerShell Download Cradle',
    mode: 'offline',
    file: 'encoded_powershell.ndjson',
    description: 'Encoded PowerShell with IEX + DownloadString - classic staged payload delivery.',
    tier: 'A',
    mitre: ['T1059.001', 'T1071.001'],
    event_ids: [1],
    expected_detections: [
      { alert_type: 'powershell_obfuscation', min_score: 95, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'An attacker runs powershell.exe with a Base64-encoded command that decodes to IEX (New-Object Net.WebClient).DownloadString() - a textbook download cradle used to pull second-stage payloads from an external server.',
    telemetry_highlights: [
      'EID 1: powershell.exe -enc flag with embedded IEX + DownloadString',
      'Parent: explorer.exe (user-initiated)',
    ],
  },
  {
    id: 'schtasks-persistence',
    name: 'Scheduled Task Persistence',
    mode: 'offline',
    file: 'schtasks_persistence.ndjson',
    description: 'schtasks.exe /Create with encoded PowerShell payload, running as SYSTEM.',
    tier: 'A',
    mitre: ['T1053.005'],
    event_ids: [1],
    expected_detections: [
      { alert_type: 'persistence_schtasks_create', min_score: 100, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'An attacker creates a scheduled task with a randomized name (Updater9A4D2F11), embedding a hidden PowerShell script from the Temp directory running as SYSTEM with HIGHEST privileges - a persistence mechanism for maintaining access.',
    telemetry_highlights: [
      'EID 1: schtasks.exe /Create /TN Updater9A4D2F11 /RU SYSTEM /RL HIGHEST',
      'Task action: powershell -nop -w hidden pointing to Temp script',
      'Parent: cmd.exe',
    ],
  },
  {
    id: 'lolbin-outbound',
    name: 'LOLBin Outbound (mshta.exe)',
    mode: 'offline',
    file: 'lolbin_outbound.ndjson',
    description: 'mshta.exe launched from suspicious path making outbound connection to public IP.',
    tier: 'A',
    mitre: ['T1218.005', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [
      { alert_type: 'lolbin_outbound', min_score: 90, queue: 'soc_malware', confidence: 'high' },
      { alert_type: 'suspicious_path_outbound', min_score: 80, queue: 'soc_policy', confidence: 'medium' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alert_A002_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'mshta.exe (a Living-off-the-Land binary) is launched from %AppData%\\Roaming and makes an outbound HTTPS connection to 8.8.8.8:443. This triggers both LOLBin-outbound and suspicious-path-outbound detections - a dual-signal pattern common in real intrusions.',
    telemetry_highlights: [
      'EID 1: mshta.exe from C:\\Users\\user\\AppData\\Roaming\\',
      'EID 3: outbound connection to 8.8.8.8:443 (public, non-Microsoft)',
    ],
  },
  {
    id: 'advanced-injection-escalated',
    name: 'Advanced Injection + Escalation',
    mode: 'offline',
    file: 'advanced_injection_escalated.ndjson',
    description: 'PowerShell DefineDynamicAssembly reflection with public outbound - escalates to soc_malware.',
    tier: 'A',
    mitre: ['T1059.001', 'T1055'],
    event_ids: [1, 3],
    expected_detections: [
      { alert_type: 'powershell_advanced_injection', min_score: 80, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'PowerShell uses .NET Reflection.Emit (DefineDynamicAssembly) to build and run code in memory - a technique used by frameworks like PowerSploit and Cobalt Strike. Paired with an outbound connection to a public non-Microsoft IP, this triggers the advanced_combo escalator pathway to soc_malware.',
    telemetry_highlights: [
      'EID 1: powershell.exe with DefineDynamicAssembly + Reflection.Emit in command line',
      'EID 3: outbound to 8.8.4.4:443 (public, non-Microsoft)',
    ],
  },
  {
    id: 'obfuscated-powershell-critical-combo',
    name: 'Obfuscated PowerShell Critical Combo',
    mode: 'offline',
    file: 'obfuscated_powershell_critical_combo.ndjson',
    description: 'Encoded PowerShell + IEX + public outbound + temp script drop - maximum escalation.',
    tier: 'A',
    mitre: ['T1059.001', 'T1071.001', 'T1105'],
    event_ids: [1, 3, 11],
    expected_detections: [
      { alert_type: 'powershell_obfuscation', min_score: 90, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'A full-chain attack: encoded PowerShell with IEX + DownloadString makes a public outbound connection AND drops a .ps1 script into %TEMP%. This combination triggers the critical_combo escalator - the highest-severity pathway in the detection engine.',
    telemetry_highlights: [
      'EID 1: powershell.exe -enc with IEX + DownloadString',
      'EID 3: outbound to 1.1.1.1:443 (public, non-Microsoft)',
      'EID 11: C:\\Users\\user\\AppData\\Local\\Temp\\stage.ps1 written',
    ],
  },
  {
    id: 'suspicious-path-outbound',
    name: 'Suspicious Path Outbound',
    mode: 'offline',
    file: 'suspicious_path_outbound.ndjson',
    description: 'Binary in %AppData%\\Roaming making HTTPS connection to external IP.',
    tier: 'B',
    mitre: ['T1036', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [
      { alert_type: 'suspicious_path_outbound', min_score: 80, queue: 'soc_policy', confidence: 'medium' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'A binary (updater.exe) running from the %AppData%\\Roaming directory makes an outbound HTTPS connection to a public IP. Legitimate software rarely executes from Roaming with outbound connections - this pattern catches drop-and-execute implants.',
    telemetry_highlights: [
      'EID 1: C:\\Users\\user\\AppData\\Roaming\\updater.exe',
      'EID 3: outbound to 45.83.1.5:443 (public, non-Microsoft)',
    ],
  },

  {
    id: 'rundll32-outbound-public',
    name: 'rundll32.exe Outbound to Public IP',
    mode: 'offline',
    file: 'rundll32_outbound_public.ndjson',
    description: 'rundll32.exe running JavaScript protocol handler with public HTTP outbound.',
    tier: 'B',
    mitre: ['T1218.011', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [
      { alert_type: 'lolbin_outbound', min_score: 90, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'rundll32.exe abuses the javascript: protocol handler to load an HTA payload from an external URL - a well-documented LOLBin technique for code execution. The outbound HTTP connection to a public IP triggers the LOLBin-outbound detection at high confidence.',

    telemetry_highlights: [
      'EID 1: rundll32.exe javascript protocol handler payload launch',
      'EID 3: outbound to 8.8.8.8:80 (public, non-Microsoft)',
    ],
  },
  {
    id: 'schtasks-persistence-cmd-dropper',
    name: 'Scheduled Task via cmd Dropper',
    mode: 'offline',
    file: 'schtasks_persistence_cmd_dropper.ndjson',
    description: 'schtasks /Create with cmd /c wrapping a hidden PowerShell script from Temp.',
    tier: 'B',
    mitre: ['T1053.005', 'T1059.003'],
    event_ids: [1],
    expected_detections: [
      { alert_type: 'persistence_schtasks_create', min_score: 85, queue: 'soc_malware', confidence: 'high' },
    ],
    expected_artifacts: ['alert_A001_bundle.json', 'alerts.csv', 'report.md', 'timeline.csv'],
    what_we_simulate: 'Variant of schtasks persistence: the task action wraps cmd /c -> powershell pointing to a script in %TEMP%. The randomized task name and Temp path trigger random-token and suspicious-action scoring bumps.',
    telemetry_highlights: [
      'EID 1: schtasks.exe /Create /TN WinUpdate7F3A91BC /SC ONLOGON',
      'Task action: cmd /c powershell -nop -w hidden -File ...\\Temp\\boot.ps1',
    ],
  },
  {
    id: 'suppression-proof',
    name: 'Suppression Proof (Allowlist Validation)',
    mode: 'offline',
    file: 'suppression_proof.ndjson',
    description: 'Benign-looking processes that should be suppressed by the default allowlist.',
    tier: 'B',
    mitre: [],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'stats.json'],
    pass_criteria: 'no_alerts',
    what_we_simulate: 'Runs allowlisted processes (MsMpEng.exe, chrome.exe) to verify the suppression engine correctly drops alerts for trusted binaries. A passing run means zero alerts emitted - proving the allowlist works as intended.',
    telemetry_highlights: [
      'EID 1: MsMpEng.exe (Windows Defender)',
      'EID 3: chrome.exe outbound (trusted browser)',
      'Expected: 0 alerts emitted, suppressed events > 0',
    ],
  },
  {
    id: 'live-online-alert-recognition',
    name: 'Live Online Alert Recognition',
    mode: 'live',
    description: 'Live query validation for online telemetry and alert schema recognition.',
    tier: 'B',
    mitre: ['T1059.001', 'T1071.001'],
    event_ids: [1, 3, 11],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Queries the last 15m of live telemetry and verifies detected alerts are fully classified (type, queue, confidence, and routing metadata).',
    telemetry_highlights: [
      'Live mode: triage fetch against OpenSearch/Wazuh indexer',
      'Agent selector: all agents by default (set agent_name/agent_id for scoped tests)',
      'Pass criteria: at least one alert, all alerts recognized with queue/confidence/routing fields',
    ],
  },
  {
    id: 'live-critical-combo-script-network-dropper',
    name: 'Live: Critical Combo (Script + Network + Dropper)',
    mode: 'live',
    description: 'Obfuscated script execution with outbound network activity and a user-writable payload drop.',
    tier: 'A',
    mitre: ['T1059.001', 'T1071.001', 'T1105'],
    event_ids: [1, 3, 11],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Validates the highest-risk chain in live telemetry: script abuse plus outbound traffic plus payload staging in user-writable folders.',
    telemetry_highlights: [
      'Signals: encoded/obfuscated script execution + public outbound + Temp/AppData/Downloads write',
      'Detection anchor: powershell_obfuscation at malware queue/high confidence',
      'Live guardrail: all returned alerts must include recognition metadata fields',
    ],
  },
  {
    id: 'live-lolbin-c2-execution',
    name: 'Live: LOLBin C2 Execution',
    mode: 'live',
    description: 'LOLBin launch with outbound connection from suspicious parent/path context.',
    tier: 'A',
    mitre: ['T1218', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Tracks mshta/rundll32/regsvr32/certutil/bitsadmin style execution with C2-like outbound networking.',
    telemetry_highlights: [
      'Signals: LOLBin execution from unusual lineage or user-writable path',
      'Signals: outbound connection to public destination',
      'Detection anchor: lolbin_outbound with high confidence',
    ],
  },
  {
    id: 'live-persistence-suspicious-payload',
    name: 'Live: Persistence with Suspicious Payload',
    mode: 'live',
    description: 'Scheduled task persistence where task action points to encoded or user-writable payload.',
    tier: 'A',
    mitre: ['T1053.005', 'T1059.001'],
    event_ids: [1],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Validates persistence via schtasks/service style tasking tied to encoded command lines or user-writable script paths.',
    telemetry_highlights: [
      'Signals: schtasks /create or equivalent service/task persistence activity',
      'Signals: payload reference in Temp/AppData/Downloads/Public path',
      'Detection anchor: persistence_schtasks_create',
    ],
  },
  {
    id: 'live-user-writable-binary-execution',
    name: 'Live: User-Writable Binary Execution',
    mode: 'live',
    description: 'Executable launched from user-writable directory followed quickly by network activity.',
    tier: 'A',
    mitre: ['T1036', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Detects drop-and-run behavior from AppData/Temp/Downloads/Public paths coupled with outbound traffic.',
    telemetry_highlights: [
      'Signals: executable path under AppData/Temp/Downloads/Public',
      'Signals: outbound network event close to process creation',
      'Detection anchor: suspicious_path_outbound',
    ],
  },
  {
    id: 'live-masquerading-system-paths',
    name: 'Live: Masquerading in System Paths',
    mode: 'live',
    description: 'Trusted-looking process names executing from non-standard locations with suspicious command behavior.',
    tier: 'A',
    mitre: ['T1036', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Highlights masquerading tradecraft where binaries mimic trusted names but run from attacker-controlled paths.',
    telemetry_highlights: [
      'Signals: trusted binary name in non-standard image path',
      'Signals: suspicious command line and/or outbound destination',
      'Detection anchor: suspicious_path_outbound as path anomaly proxy',
    ],
  },
  {
    id: 'live-process-chain-anomaly',
    name: 'Live: Process Chain Anomaly',
    mode: 'live',
    description: 'Rare parent-child process chains with scripting or LOLBin follow-on activity.',
    tier: 'A',
    mitre: ['T1204', 'T1059.001', 'T1218'],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Prioritizes uncommon process ancestry such as office->powershell, browser->cmd, explorer->regsvr32.',
    telemetry_highlights: [
      'Signals: rare parent-child execution lineage',
      'Signals: downstream obfuscation, LOLBin, or outbound behavior',
      'Detection anchor: high-risk script/LOLBin detections in anomalous lineage context',
    ],
  },
  {
    id: 'live-burst-spread-behavior',
    name: 'Live: Burst/Spread Behavior',
    mode: 'live',
    description: 'Many suspicious process launches or repeated suspicious retries in a short time window.',
    tier: 'B',
    mitre: ['T1105', 'T1071.001'],
    event_ids: [1, 3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Flags fan-out process activity and repeated suspicious outbound retries that often indicate propagation or unstable malware loops.',
    telemetry_highlights: [
      'Signals: burst of suspicious process starts in short interval',
      'Signals: repeated retries to multiple destinations',
      'Pass criteria: at least 4 recognized alerts with valid routing metadata',
    ],
  },
  {
    id: 'live-beacon-like-outbound-pattern',
    name: 'Live: Beacon-Like Outbound Pattern',
    mode: 'live',
    description: 'Repeated periodic outbound behavior by the same process/destination tuple.',
    tier: 'B',
    mitre: ['T1071.001'],
    event_ids: [3],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Monitors low-and-slow C2 style periodic outbound patterns where individual events look weak but repeated cadence is suspicious.',
    telemetry_highlights: [
      'Signals: repeated outbound contacts with similar process/IP:port tuple',
      'Signals: short recurring interval behavior',
      'Pass criteria: at least 3 recognized alerts with complete schema fields',
    ],
  },
  {
    id: 'live-suppression-guardrail-alert',
    name: 'Live: Suppression Guardrail Alert',
    mode: 'live',
    description: 'Watch for risky over-suppression conditions while maintaining validated live alert schema.',
    tier: 'B',
    mitre: ['T1562.001'],
    event_ids: [1, 3, 11],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Provides a guardrail scenario for live tuning: if malicious categories vanish unexpectedly, investigate suppression policy drift.',
    telemetry_highlights: [
      'Signals: sudden mismatch between suspicious telemetry and emitted alert volume',
      'Operational check: review suppression_hits and allowlist drift in stats output',
      'Pass criteria: at least one recognized alert present for schema/routing validation',
    ],
  },
  {
    id: 'live-executive-hot-host-alert',
    name: 'Live: Executive Hot Host Alert',
    mode: 'live',
    description: 'Host-level meta alert lens when cumulative suspicious activity crosses incident threshold.',
    tier: 'A',
    mitre: ['T1071.001', 'T1105', 'T1059.001'],
    event_ids: [1, 3, 11],
    expected_detections: [],
    expected_artifacts: ['alerts.csv', 'report.md', 'timeline.csv', 'stats.json', 'run_metadata.json'],
    pass_criteria: 'recognized_alert_schema',
    min_alerts_emitted: 1,
    live: {
      time_preset: '15m',
      verify_tls: false,
    },
    what_we_simulate: 'Escalates multi-alert host pressure into an executive-friendly priority signal when several medium findings stack quickly.',
    telemetry_highlights: [
      'Signals: cumulative risk from multiple medium/high alerts on one host',
      'Use case: collapse noisy medium alerts into one high-priority incident lens',
      'Pass criteria: at least 5 recognized alerts in the selected live window',
    ],
  },
];

/* Default run results */
export function emptyRunResult(scenarioId: string): ScenarioRunResult {
  return {
    scenario_id: scenarioId,
    status: 'not_run',
    alerts_emitted: 0,
    passed: null,
    outputs: [],
  };
}


