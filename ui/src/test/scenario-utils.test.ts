import { describe, expect, it } from 'vitest';
import type { Alert } from '@/types';
import { SCENARIOS } from '@/data/scenarios';
import {
  buildScenarioParams,
  evaluateScenario,
  isRecognizedAlert,
} from '@/features/simulate/scenario-utils';

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    alert_id: 'A001',
    utc_time: '2026-02-26T00:00:00Z',
    score: 95,
    alert_type: 'powershell_obfuscation',
    category: 'malware_execution',
    queue: 'soc_malware',
    confidence: 'high',
    reason: 'PowerShell obfuscation',
    routing_why: 'Routed to soc_malware',
    image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    command_line: 'powershell.exe -enc ...',
    parent_image: 'C:\\Windows\\explorer.exe',
    destination_ip: '8.8.8.8',
    destination_port: 443,
    process_guid: '{GUID}',
    tags: ['batcave'],
    ...overrides,
  };
}

describe('scenario utils', () => {
  it('builds offline scenario params with sample input file', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'encoded-powershell');
    expect(scenario).toBeDefined();

    const params = buildScenarioParams(scenario!, 'SIM-CASE-001');
    expect(params.mode).toBe('offline');
    expect(params.input_file).toBe('samples/scenario_gym/encoded_powershell.ndjson');
    expect(params.case_id).toBe('SIM-CASE-001');
  });

  it('builds live scenario params without offline input file', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'live-online-alert-recognition');
    expect(scenario).toBeDefined();

    const params = buildScenarioParams(scenario!, 'SIM-CASE-002');
    expect(params.mode).toBe('live');
    expect(params.input_file).toBeUndefined();
    expect(params.time_preset).toBe('15m');
    expect(params.agent_name).toBeUndefined();
    expect(params.verify_tls).toBe(false);
  });

  it('evaluates expected detections for deterministic offline scenarios', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'encoded-powershell');
    expect(scenario).toBeDefined();

    const passing = evaluateScenario([makeAlert()], scenario!);
    expect(passing.passed).toBe(true);

    const failing = evaluateScenario([makeAlert({ alert_type: 'lolbin_outbound' })], scenario!);
    expect(failing.passed).toBe(false);
    expect(failing.error).toContain('Missing expected detections');
  });

  it('evaluates suppression-proof as no-alerts expected', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'suppression-proof');
    expect(scenario).toBeDefined();

    expect(evaluateScenario([], scenario!).passed).toBe(true);
    expect(evaluateScenario([makeAlert()], scenario!).passed).toBe(false);
  });

  it('recognizes alert schema for live scenario checks', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'live-online-alert-recognition');
    expect(scenario).toBeDefined();

    const validAlert = makeAlert();
    expect(isRecognizedAlert(validAlert)).toBe(true);

    const malformedAlert = makeAlert({ routing_why: '' });
    expect(isRecognizedAlert(malformedAlert)).toBe(false);

    expect(evaluateScenario([validAlert], scenario!).passed).toBe(true);
    expect(evaluateScenario([], scenario!).passed).toBe(false);
    expect(evaluateScenario([malformedAlert], scenario!).passed).toBe(false);
  });

  it('enforces recognition metadata for live expected-detection scenarios', () => {
    const scenario = SCENARIOS.find((item) => item.id === 'live-lolbin-c2-execution');
    expect(scenario).toBeDefined();

    const validAlert = makeAlert({
      alert_type: 'lolbin_outbound',
      score: 95,
      queue: 'soc_malware',
      confidence: 'high',
    });
    expect(evaluateScenario([validAlert], scenario!).passed).toBe(true);

    const malformedAlert = makeAlert({
      alert_type: 'lolbin_outbound',
      score: 95,
      queue: 'soc_malware',
      confidence: 'high',
      routing_why: '',
    });
    const malformed = evaluateScenario([malformedAlert], scenario!);
    expect(malformed.passed).toBe(false);
    expect(malformed.error).toContain('Alert recognition failed');
  });
});
