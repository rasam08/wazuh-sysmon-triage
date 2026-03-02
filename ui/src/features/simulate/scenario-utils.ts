import type { Alert, RunParams } from '@/types';
import type {
  ScenarioArtifact,
  ScenarioDefinition,
  ScenarioExpectation,
  ScenarioPassCriteria,
} from '@/data/scenarios';

const VALID_QUEUES = new Set(['soc_malware', 'soc_policy', 'soc_dev', 'soc_info']);
const VALID_CONFIDENCE = new Set(['low', 'medium', 'high']);

interface ScenarioEvaluationResult {
  passed: boolean;
  error?: string;
}

export function buildScenarioCaseId(scenarioId: string): string {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(-10);
  const id = scenarioId.replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 10);
  return `SIM-${id}-${stamp}`;
}

export function buildScenarioParams(scenario: ScenarioDefinition, caseId: string): RunParams {
  const defaultQueues: RunParams['queues'] = ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'];
  const baseParams = {
    profile: 'soc' as const,
    queues: defaultQueues,
    include_dev_queue: true,
    min_alert_score: 0,
    out_dir: '../out',
    case_id: caseId,
    dry_run: false,
    alerts_only: false,
    print_stats: true,
  };

  if (scenario.mode === 'offline') {
    if (!scenario.file) {
      throw new Error(`Offline scenario "${scenario.id}" is missing file`);
    }
    return {
      ...baseParams,
      mode: 'offline',
      time_preset: '2h',
      input_file: `samples/scenario_gym/${scenario.file}`,
      verify_tls: false,
    };
  }

  const live = scenario.live ?? { time_preset: '2h' };
  return {
    ...baseParams,
    mode: 'live',
    time_preset: live.time_preset,
    start: live.start,
    end: live.end,
    agent_name: live.agent_name,
    agent_id: live.agent_id,
    verify_tls: live.verify_tls,
  };
}

function matchesExpectation(alert: Alert, expected: ScenarioExpectation): boolean {
  return (
    alert.alert_type === expected.alert_type
    && alert.score >= expected.min_score
    && alert.queue === expected.queue
    && alert.confidence === expected.confidence
  );
}

function resolvePassCriteria(scenario: ScenarioDefinition): ScenarioPassCriteria {
  if (scenario.pass_criteria) return scenario.pass_criteria;
  if (scenario.expected_detections.length === 0) return 'no_alerts';
  return 'expected_detections';
}

export function isRecognizedAlert(alert: Alert): boolean {
  if (!alert.alert_id?.trim()) return false;
  if (!alert.alert_type?.trim()) return false;
  if (!Number.isFinite(alert.score) || alert.score < 0 || alert.score > 100) return false;
  if (!VALID_QUEUES.has(alert.queue)) return false;
  if (!VALID_CONFIDENCE.has(alert.confidence)) return false;
  if (!alert.reason?.trim()) return false;
  if (!alert.routing_why?.trim()) return false;
  return true;
}

export function evaluateScenario(alerts: Alert[], scenario: ScenarioDefinition): ScenarioEvaluationResult {
  if (scenario.min_alerts_emitted != null && alerts.length < scenario.min_alerts_emitted) {
    return {
      passed: false,
      error: `Expected at least ${scenario.min_alerts_emitted} alerts, got ${alerts.length}`,
    };
  }

  const criteria = resolvePassCriteria(scenario);
  const requiresRecognition = scenario.mode === 'live' || criteria === 'recognized_alert_schema';
  if (requiresRecognition) {
    const invalid = alerts.find((alert) => !isRecognizedAlert(alert));
    if (invalid) {
      return {
        passed: false,
        error: `Alert recognition failed for ${invalid.alert_id || '<missing-id>'}`,
      };
    }
  }

  if (criteria === 'recognized_alert_schema') {
    return { passed: true };
  }

  if (criteria === 'no_alerts') {
    if (alerts.length === 0) return { passed: true };
    return { passed: false, error: `Expected 0 alerts, got ${alerts.length}` };
  }

  const missing = scenario.expected_detections.filter(
    (expected) => !alerts.some((alert) => matchesExpectation(alert, expected)),
  );

  if (missing.length === 0) return { passed: true };
  const expectedList = missing.map((item) => item.alert_type).join(', ');
  return { passed: false, error: `Missing expected detections: ${expectedList}` };
}

export function buildOutputArtifacts(alerts: Alert[]): ScenarioArtifact[] {
  const artifacts: ScenarioArtifact[] = [
    { label: 'alerts', filename: 'alerts.csv' },
    { label: 'timeline', filename: 'timeline.csv' },
    { label: 'report', filename: 'report.md' },
    { label: 'stats', filename: 'stats.json' },
    { label: 'run metadata', filename: 'run_metadata.json' },
  ];

  for (const alert of alerts) {
    artifacts.push({
      label: `bundle ${alert.alert_id}`,
      filename: `alert_${alert.alert_id}_bundle.json`,
    });
  }

  const deduped = new Map<string, ScenarioArtifact>();
  for (const item of artifacts) deduped.set(item.filename, item);
  return Array.from(deduped.values());
}
