import type { AlertQueue, Profile, RunMode, RunParams } from './validators';

export class ArtifactError extends Error {
  readonly status: number;

  constructor(message: string, status = 500) {
    super(message);
    this.name = 'ArtifactError';
    this.status = status;
  }
}

interface ApiRunStage {
  name: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  status: 'success' | 'error';
}

export interface ApiRunMetadata {
  run_id: string;
  case_id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  params: RunParams;
  schema_version: string;
  stages: ApiRunStage[];
}

export interface ApiRunStats {
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

export interface ApiRun {
  id: string;
  params: RunParams;
  status: 'pending' | 'running' | 'success' | 'failed' | 'cancelled';
  job_id?: string;
  queued_at?: string;
  progress_pct?: number;
  cancel_reason?: string;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  alert_count?: number;
  error?: string;
  metadata?: ApiRunMetadata;
  stats?: ApiRunStats;
}

export interface ApiTimelineEvent {
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

export interface ApiProcessNode {
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

export interface ApiArtifact {
  path: string;
  created_at: string;
  creating_process_guid: string;
  creating_image: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  tags: string[];
}

export interface ApiProcessTree {
  schema_version: string;
  agent: { name: string; id: string };
  time_range: { start: string; end: string };
  nodes: ApiProcessNode[];
  edges: Array<{ parent_guid: string; child_guid: string; reason: string }>;
  artifacts: ApiArtifact[];
}

export interface ApiResolvedQuery {
  index: string;
  start: string;
  end: string;
  agent_id?: string;
  agent_name?: string;
  event_ids: number[];
  size: number;
}

export interface ApiAlert {
  alert_id: string;
  utc_time: string;
  score: number;
  alert_type: string;
  category: 'malware_execution' | 'c2_outbound' | 'persistence' | 'policy_violation' | 'developer_tooling' | 'unknown';
  queue: AlertQueue;
  confidence: 'low' | 'medium' | 'high';
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

export interface ApiAlertBundle {
  alert: ApiAlert;
  related_events: ApiTimelineEvent[];
  process_context: ApiProcessNode[];
  network_context: Array<{
    process_guid: string;
    image: string;
    destination_ip: string;
    destination_port: number;
    protocol: string;
    suspicious: boolean;
  }>;
}

export interface ApiCase {
  case_id: string;
  run_id: string;
  time_range: { start: string; end: string };
  profile: Profile;
  mode: RunMode;
  schema_version: string;
  stats: ApiRunStats;
  alerts: ApiAlert[];
  timeline: ApiTimelineEvent[];
  process_tree: ApiProcessTree;
  report_md: string;
  query: ApiResolvedQuery;
  artifacts: ApiArtifact[];
}

export interface CaseArtifacts {
  dir: string;
  caseId: string;
  metadata: Record<string, unknown> | null;
  statsRaw: Record<string, unknown> | null;
  queryRaw: Record<string, unknown> | null;
  reportMd: string;
  processTreeRaw: Record<string, unknown> | null;
  timelineRawRows: Record<string, string>[];
  alerts: ApiAlert[];
  bundlesById: Map<string, ApiAlertBundle>;
}
