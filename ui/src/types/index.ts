/* ─── Alert ─── */
export type AlertCategory =
  | 'malware_execution'
  | 'c2_outbound'
  | 'persistence'
  | 'policy_violation'
  | 'developer_tooling'
  | 'unknown';

export type AlertQueue = 'soc_malware' | 'soc_policy' | 'soc_dev' | 'soc_info';

export type Confidence = 'low' | 'medium' | 'high';

export interface Alert {
  alert_id: string;
  utc_time: string;
  score: number;
  alert_type: string;
  category: AlertCategory;
  queue: AlertQueue;
  confidence: Confidence;
  reason: string;
  routing_why: string;
  image: string;
  command_line: string;
  parent_image: string;
  destination_ip: string;
  destination_port: number | null;
  process_guid: string;
  tags: string[];
  rule_id?: string;
  rule_name?: string;
  suppressed_related_rules?: string[];
  suppressed_related_count?: number;
  derived_fields?: string[];
}

/* ─── Alert Bundle ─── */
export interface AlertBundle {
  alert: Alert;
  related_events: TimelineEvent[];
  process_context: ProcessNode[];
  network_context: NetworkActivity[];
}

/* ─── Timeline ─── */
export interface TimelineEvent {
  timestamp: string;
  event_id: number;
  image: string;
  command_line: string;
  parent_image: string;
  target_filename: string;
  user: string;
  rule_id: string;
  agent_name: string;
  agent_id: string;
}

/* ─── Process Tree ─── */
export interface ProcessNode {
  guid: string;
  pid: number;
  image: string;
  cmdline: string;
  user: string;
  first_seen: string;
  last_seen: string;
  synthetic: boolean;
  tags: string[];
}

export interface ProcessEdge {
  parent_guid: string;
  child_guid: string;
  reason: string;
}

export interface Artifact {
  path: string;
  created_at: string;
  creating_process_guid: string;
  creating_image: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  tags: string[];
}

export interface ProcessTree {
  schema_version: string;
  agent: { name: string; id: string };
  time_range: { start: string; end: string };
  nodes: ProcessNode[];
  edges: ProcessEdge[];
  artifacts: Artifact[];
}

/* ─── Network Activity ─── */
export interface NetworkActivity {
  process_guid: string;
  image: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  suspicious: boolean;
}

/* ─── Stats ─── */
export interface RunStats {
  total_events: number;
  by_event_id: Record<string, number>;
  alerts_generated: number;
  alerts_suppressed: number;
  suppression_hits: Record<string, number>;
  dropped_events: number;
  dropped_by_reason: Record<string, number>;
  queues: Record<string, number>;
  categories: Record<string, number>;
  confidence_distribution: Record<string, number>;
  network_connections: number;
  suspicious_destinations: number;
}

/* ─── Run Metadata ─── */
export interface RunMetadata {
  run_id: string;
  case_id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  params: RunParams;
  schema_version: string;
  stages: StageResult[];
}

export interface StageResult {
  name: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  status: 'success' | 'error';
  error?: string;
}

/* ─── Query ─── */
export interface ResolvedQuery {
  index: string;
  start: string;
  end: string;
  agent_id?: string;
  agent_name?: string;
  event_ids: number[];
  size: number;
}

/* ─── Run Params (mirrors CLI config) ─── */
export type RunMode = 'live' | 'offline';
export type Profile = 'soc' | 'dev' | 'lab';
export type TimePreset = '15m' | '2h' | '24h' | '7d' | 'today' | 'yesterday' | 'custom';

export interface RunParams {
  mode: RunMode;
  profile: Profile;
  time_preset: TimePreset;
  start?: string;
  end?: string;
  agent_name?: string;
  agent_id?: string;
  input_file?: string;
  queues: AlertQueue[];
  include_dev_queue: boolean;
  min_alert_score: number;
  out_dir: string;
  case_id: string;
  dry_run: boolean;
  alerts_only: boolean;
  print_stats: boolean;
  verify_tls?: boolean;
  allowlist_images?: string[];
  allow_overwrite?: boolean;
  force?: boolean;
}

export interface HealthStatus {
  checked_at: string;
  profile: Profile;
  cli_available?: boolean;
  opensearch_host: string | null;
  opensearch_connectivity: 'reachable' | 'unreachable' | 'not_configured' | 'unknown';
  opensearch_http_status: number | null;
  tls_mode: 'verify' | 'insecure' | 'unknown';
  last_successful_fetch_at: string | null;
  error?: string;
}

/* ─── Run State (UI) ─── */
export type RunStatus = 'pending' | 'running' | 'success' | 'failed';
export type RunStage = 'fetch' | 'normalize' | 'correlate' | 'detect' | 'render';

export interface Run {
  id: string;
  params: RunParams;
  status: RunStatus;
  current_stage?: RunStage;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  alert_count?: number;
  error?: string;
  metadata?: RunMetadata;
  stats?: RunStats;
}

/* ─── Case ─── */
export interface Case {
  case_id: string;
  run_id: string;
  time_range: { start: string; end: string };
  profile: Profile;
  mode: RunMode;
  schema_version: string;
  stats: RunStats;
  alerts: Alert[];
  timeline: TimelineEvent[];
  process_tree: ProcessTree;
  report_md: string;
  query: ResolvedQuery;
  artifacts: Artifact[];
}

/* ─── Filters ─── */
export interface AlertFilters {
  search: string;
  queues: AlertQueue[];
  categories: AlertCategory[];
  confidences: Confidence[];
  score_min: number;
  score_max: number;
  tags: string[];
}

export type SortField = 'score' | 'utc_time' | 'queue' | 'confidence' | 'category';
export type SortDirection = 'asc' | 'desc';

export interface AlertSort {
  field: SortField;
  direction: SortDirection;
}
