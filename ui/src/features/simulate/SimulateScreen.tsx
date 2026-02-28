import React, { useCallback, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, Badge, Button, KpiTile, EmptyState } from '@/components';
import {
  SCENARIOS,
  emptyRunResult,
  type ScenarioDefinition,
  type ScenarioRunResult,
  type ScenarioStatus,
} from '@/data/scenarios';
import { startRun, fetchAlerts } from '@/data/api';
import { useToastStore } from '@/stores';
import type { RunMode } from '@/types';

import {
  buildOutputArtifacts,
  buildScenarioCaseId,
  buildScenarioParams,
  evaluateScenario,
} from './scenario-utils';

const STAGE_LABELS = ['fetch', 'normalize', 'correlate', 'detect', 'render'] as const;

const STATUS_BADGE: Record<ScenarioStatus, { variant: 'muted' | 'info' | 'success' | 'danger'; label: string }> = {
  not_run: { variant: 'muted', label: 'Not Run' },
  running: { variant: 'info', label: 'Running' },
  passed: { variant: 'success', label: 'Passed' },
  failed: { variant: 'danger', label: 'Failed' },
  canceled: { variant: 'muted', label: 'Canceled' },
};

function fmtMs(ms?: number): string {
  if (!ms) return '-';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function isAbort(err: unknown): boolean {
  return err instanceof DOMException && err.name === 'AbortError';
}

function expectationLabel(scenario: ScenarioDefinition): string {
  if (scenario.pass_criteria === 'recognized_alert_schema') {
    const minAlerts = scenario.min_alerts_emitted ?? 0;
    return `Expected: ${minAlerts}+ recognized alert${minAlerts === 1 ? '' : 's'}`;
  }
  const recognitionSuffix = scenario.mode === 'live' ? ' + recognized schema' : '';
  if (scenario.expected_detections.length === 0) {
    return `Expected: 0 alerts${recognitionSuffix}`;
  }
  return `Expected: ${scenario.expected_detections.length} alert${scenario.expected_detections.length !== 1 ? 's' : ''}${recognitionSuffix}`;
}

export default function SimulateScreen() {
  const navigate = useNavigate();
  const [results, setResults] = useState<Record<string, ScenarioRunResult>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [modeFilter, setModeFilter] = useState<RunMode>('offline');
  const [runningAll, setRunningAll] = useState(false);
  const controllersRef = useRef<Record<string, AbortController>>({});
  const cancelRequestedRef = useRef(false);
  const addToast = useToastStore((s) => s.addToast);

  const getResult = (id: string): ScenarioRunResult => results[id] ?? emptyRunResult(id);
  const visibleScenarios = useMemo(
    () => SCENARIOS.filter((scenario) => scenario.mode === modeFilter),
    [modeFilter],
  );
  const selected = visibleScenarios.find((s) => s.id === selectedId) ?? null;

  const cancelScenario = useCallback((scenarioId: string) => {
    const controller = controllersRef.current[scenarioId];
    if (controller) controller.abort();
  }, []);

  const cancelAll = useCallback(() => {
    cancelRequestedRef.current = true;
    Object.values(controllersRef.current).forEach((controller) => controller.abort());
    addToast('info', 'Cancel requested for running scenarios');
  }, [addToast]);

  const runScenario = useCallback(async (scenario: ScenarioDefinition) => {
    const startedAt = new Date().toISOString();
    const caseId = buildScenarioCaseId(scenario.id);
    const controller = new AbortController();
    controllersRef.current[scenario.id] = controller;

    setResults((prev) => ({
      ...prev,
      [scenario.id]: {
        ...emptyRunResult(scenario.id),
        status: 'running',
        started_at: startedAt,
        case_id: caseId,
      },
    }));

    try {
      const run = await startRun(buildScenarioParams(scenario, caseId), { signal: controller.signal });
      if (run.status !== 'success') {
        throw new Error(run.error || 'Scenario run failed');
      }
      const alertPayload = await fetchAlerts(caseId, { signal: controller.signal });
      const evaluation = evaluateScenario(alertPayload.alerts, scenario);
      const completedAt = run.completed_at ?? new Date().toISOString();

      const scenarioResult: ScenarioRunResult = {
        scenario_id: scenario.id,
        status: evaluation.passed ? 'passed' : 'failed',
        started_at: run.started_at,
        completed_at: completedAt,
        duration_ms: run.duration_ms ?? (new Date(completedAt).getTime() - new Date(run.started_at).getTime()),
        case_id: caseId,
        alerts_emitted: alertPayload.alerts.length,
        passed: evaluation.passed,
        outputs: buildOutputArtifacts(alertPayload.alerts),
        alerts_preview: alertPayload.alerts.slice(0, 5).map((alert) => ({
          alert_id: alert.alert_id,
          score: alert.score,
          alert_type: alert.alert_type,
          queue: alert.queue,
          confidence: alert.confidence,
          reason: alert.reason,
        })),
        error: evaluation.passed ? undefined : (evaluation.error ?? 'Scenario checks failed'),
      };

      setResults((prev) => ({ ...prev, [scenario.id]: scenarioResult }));
      addToast(
        evaluation.passed ? 'success' : 'error',
        evaluation.passed ? `Scenario "${scenario.name}" passed` : `Scenario "${scenario.name}" failed checks`,
      );
      return scenarioResult;
    } catch (err) {
      const canceled = isAbort(err) || controller.signal.aborted;
      const message = canceled ? 'Canceled by user' : (err instanceof Error ? err.message : 'Unknown error');
      const failedResult: ScenarioRunResult = {
        scenario_id: scenario.id,
        status: canceled ? 'canceled' : 'failed',
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        current_stage: undefined,
        case_id: caseId,
        alerts_emitted: 0,
        passed: canceled ? null : false,
        error: message,
        outputs: [],
      };
      setResults((prev) => ({ ...prev, [scenario.id]: failedResult }));
      if (!canceled) {
        addToast('error', `Scenario "${scenario.name}" failed: ${message}`);
      }
      return failedResult;
    } finally {
      delete controllersRef.current[scenario.id];
    }
  }, [addToast]);

  const runAll = useCallback(async () => {
    setRunningAll(true);
    cancelRequestedRef.current = false;
    for (const scenario of visibleScenarios) {
      if (cancelRequestedRef.current) break;
      const result = await runScenario(scenario);
      if (result.status === 'canceled' || cancelRequestedRef.current) break;
    }
    setRunningAll(false);
    cancelRequestedRef.current = false;
  }, [runScenario, visibleScenarios]);

  const visibleResults = visibleScenarios.map((scenario) => getResult(scenario.id));
  const totalRun = visibleResults.filter((r) => r.status !== 'not_run').length;
  const passed = visibleResults.filter((r) => r.status === 'passed').length;
  const failed = visibleResults.filter((r) => r.status === 'failed').length;
  const canceled = visibleResults.filter((r) => r.status === 'canceled').length;
  const running = visibleResults.filter((r) => r.status === 'running').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Scenario Gym</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {visibleScenarios.length} {modeFilter} scenarios - execute runs and validate detections
          </p>
          {modeFilter === 'live' && (
            <p className="text-xs text-amber-400/90 mt-1">
              Live scenarios are passive validation checks. Generate activity on monitored hosts, then rerun to verify detections.
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant={modeFilter === 'offline' ? 'secondary' : 'ghost'}
            onClick={() => {
              setModeFilter('offline');
              setSelectedId(null);
            }}
            disabled={runningAll}
          >
            Offline
          </Button>
          <Button
            size="sm"
            variant={modeFilter === 'live' ? 'secondary' : 'ghost'}
            onClick={() => {
              setModeFilter('live');
              setSelectedId(null);
            }}
            disabled={runningAll}
          >
            Live
          </Button>
          <Button size="sm" variant="secondary" onClick={() => setResults({})} disabled={runningAll || totalRun === 0}>
            Reset All
          </Button>
          {runningAll ? (
            <Button size="sm" variant="danger" onClick={cancelAll}>
              Cancel Run All
            </Button>
          ) : (
            <Button size="sm" onClick={runAll} disabled={visibleScenarios.length === 0}>
              Run All Scenarios
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {runningAll && (
          <div className="col-span-full">
            <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
              <span>Running all scenarios...</span>
              <span>{totalRun} / {visibleScenarios.length}</span>
            </div>
            <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-300"
                style={{ width: `${visibleScenarios.length > 0 ? Math.round((totalRun / visibleScenarios.length) * 100) : 0}%` }}
              />
            </div>
          </div>
        )}
        <KpiTile
          label="Scenarios"
          value={visibleScenarios.length}
          subtext={`${visibleScenarios.filter((s) => s.tier === 'A').length} Tier A, ${visibleScenarios.filter((s) => s.tier === 'B').length} Tier B`}
        />
        <KpiTile label="Executed" value={totalRun} subtext={`of ${visibleScenarios.length}`} />
        <KpiTile label="Passed" value={passed} variant="success" subtext={totalRun > 0 ? `${Math.round((passed / totalRun) * 100)}% pass rate` : undefined} />
        <KpiTile label="Failed" value={failed} variant={failed > 0 ? 'danger' : 'default'} />
        <KpiTile label="Canceled" value={canceled} variant="default" subtext={running > 0 ? `${running} running` : undefined} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-2">
          {visibleScenarios.map((scenario) => {
            const result = getResult(scenario.id);
            const isSelected = selectedId === scenario.id;
            const currentStageIndex = result.current_stage ? STAGE_LABELS.indexOf(result.current_stage) : -1;
            const stagePercent = result.current_stage ? Math.round(((currentStageIndex + 1) / STAGE_LABELS.length) * 100) : 0;

            return (
              <div
                key={scenario.id}
                onClick={() => setSelectedId(isSelected ? null : scenario.id)}
                className={`rounded-lg border px-4 py-3 cursor-pointer transition-all ${
                  isSelected ? 'border-blue-500/60 bg-blue-950/20' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-gray-200 truncate">{scenario.name}</h3>
                      <Badge variant={scenario.tier === 'A' ? 'danger' : 'muted'} size="sm">Tier {scenario.tier}</Badge>
                      <Badge variant={scenario.mode === 'live' ? 'info' : 'muted'} size="sm">{scenario.mode}</Badge>
                      {scenario.mitre.length > 0 && <span className="text-[10px] text-gray-500 font-mono">{scenario.mitre[0]}</span>}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5 truncate">{scenario.description}</p>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-[10px] text-gray-600 uppercase">EIDs: {scenario.event_ids.join(', ')}</span>
                      <span className="text-[10px] text-gray-600">
                        {expectationLabel(scenario)}
                      </span>
                      {result.duration_ms != null && <span className="text-[10px] text-gray-600">{fmtMs(result.duration_ms)}</span>}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge variant={STATUS_BADGE[result.status].variant}>{STATUS_BADGE[result.status].label}</Badge>
                    {result.status === 'running' ? (
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={(e) => {
                          e.stopPropagation();
                          cancelScenario(scenario.id);
                        }}
                      >
                        Cancel
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={runningAll}
                        onClick={(e) => {
                          e.stopPropagation();
                          void runScenario(scenario);
                        }}
                      >
                        Run
                      </Button>
                    )}
                  </div>
                </div>

                {result.status === 'running' && (
                  <div className="mt-2 space-y-1">
                    <div className="flex justify-between text-[10px] text-gray-500">
                      <span>Stage {currentStageIndex + 1}/{STAGE_LABELS.length}: {result.current_stage}</span>
                      <span>{stagePercent}%</span>
                    </div>
                    <div className="flex gap-1">
                      {STAGE_LABELS.map((stage, idx) => (
                        <div key={stage} className={`h-1 flex-1 rounded-full ${idx <= currentStageIndex ? 'bg-blue-500' : 'bg-gray-800'}`} />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="space-y-4">
          {selected ? (
            <ScenarioDetail
              scenario={selected}
              result={getResult(selected.id)}
              onRun={() => { void runScenario(selected); }}
              onCancel={() => cancelScenario(selected.id)}
              onOpenAlerts={(caseId) => navigate(`/alerts?case=${encodeURIComponent(caseId)}`)}
              onOpenCase={(caseId) => navigate(`/cases/${encodeURIComponent(caseId)}`)}
              disabled={runningAll}
            />
          ) : (
            <Card>
              <EmptyState
                title="Select a scenario"
                description="Click any scenario to view details, expectations, and run outputs."
              />
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function ScenarioDetail({
  scenario,
  result,
  onRun,
  onCancel,
  onOpenAlerts,
  onOpenCase,
  disabled,
}: {
  scenario: ScenarioDefinition;
  result: ScenarioRunResult;
  onRun: () => void;
  onCancel: () => void;
  onOpenAlerts: (caseId: string) => void;
  onOpenCase: (caseId: string) => void;
  disabled: boolean;
}) {
  const currentStageIndex = result.current_stage ? STAGE_LABELS.indexOf(result.current_stage) : -1;

  return (
    <>
      <Card title={scenario.name}>
        <div className="space-y-3">
          <p className="text-sm text-gray-400 leading-relaxed">{scenario.what_we_simulate}</p>

          <div className="flex flex-wrap gap-1.5">
            <Badge variant={scenario.tier === 'A' ? 'danger' : 'muted'}>Tier {scenario.tier}</Badge>
            <Badge variant={scenario.mode === 'live' ? 'info' : 'muted'}>{scenario.mode}</Badge>
            {scenario.mitre.map((tactic) => <Badge key={tactic} variant="info" size="sm">{tactic}</Badge>)}
            {scenario.event_ids.map((eventId) => <Badge key={eventId} variant="default" size="sm">EID {eventId}</Badge>)}
          </div>

          <div>
            <h4 className="text-xs text-gray-500 uppercase tracking-wide mb-1">Telemetry</h4>
            <ul className="space-y-1">
              {scenario.telemetry_highlights.map((item, idx) => (
                <li key={idx} className="text-xs text-gray-400 flex items-start gap-1.5">
                  <span className="text-sky-400 mt-0.5 text-[10px]">*</span>
                  <span className="font-mono">{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </Card>

      <Card title="Expected Detections">
        {scenario.pass_criteria === 'recognized_alert_schema' ? (
          <p className="text-xs text-gray-500">
            Expect recognized alerts with required fields (type, queue, confidence, routing).
            {scenario.min_alerts_emitted != null ? ` Minimum alerts: ${scenario.min_alerts_emitted}.` : ''}
          </p>
        ) : scenario.expected_detections.length === 0 ? (
          <p className="text-xs text-gray-500">No alerts expected (suppression validation)</p>
        ) : (
          <div className="space-y-2">
            {scenario.expected_detections.map((detection, idx) => (
              <div key={idx} className="flex items-center justify-between px-2 py-1.5 rounded bg-gray-800/50">
                <div>
                  <span className="text-xs text-gray-200 font-mono">{detection.alert_type}</span>
                  <div className="flex gap-1.5 mt-0.5">
                    <Badge variant={detection.queue === 'soc_malware' ? 'danger' : 'warning'} size="sm">
                      {detection.queue.replace('soc_', '')}
                    </Badge>
                    <Badge variant={detection.confidence === 'high' ? 'danger' : 'warning'} size="sm">
                      {detection.confidence}
                    </Badge>
                  </div>
                </div>
                <span className="text-lg font-bold text-gray-300">{'>='}{detection.min_score}</span>
              </div>
            ))}
            {scenario.mode === 'live' && (
              <p className="text-[11px] text-gray-500">
                Live guardrail: every alert must include id/type/score/queue/confidence/reason/routing fields.
              </p>
            )}
          </div>
        )}
      </Card>

      <Card title="Run Result">
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500">Status</span>
            <Badge variant={STATUS_BADGE[result.status].variant}>{STATUS_BADGE[result.status].label}</Badge>
          </div>
          {result.status === 'running' && result.current_stage && (
            <div className="flex justify-between">
              <span className="text-gray-500">Current Stage</span>
              <span className="text-gray-200">{result.current_stage} ({currentStageIndex + 1}/{STAGE_LABELS.length})</span>
            </div>
          )}
          {result.alerts_emitted > 0 && (
            <div className="flex justify-between">
              <span className="text-gray-500">Alerts Emitted</span>
              <span className="text-gray-200">{result.alerts_emitted}</span>
            </div>
          )}
          {result.case_id && (
            <div className="flex justify-between">
              <span className="text-gray-500">Case ID</span>
              <span className="text-gray-200 font-mono text-xs">{result.case_id}</span>
            </div>
          )}
          {result.duration_ms != null && (
            <div className="flex justify-between">
              <span className="text-gray-500">Duration</span>
              <span className="text-gray-200">{fmtMs(result.duration_ms)}</span>
            </div>
          )}
          {result.error && <p className="text-xs text-red-400">{result.error}</p>}

          {result.outputs.length > 0 && (
            <div className="pt-2 border-t border-gray-800">
              <h5 className="text-xs text-gray-500 uppercase mb-1">Outputs</h5>
              <div className="flex flex-wrap gap-1">
                {result.outputs.map((output) => <Badge key={output.filename} variant="default" size="sm">{output.filename}</Badge>)}
              </div>
            </div>
          )}

          {result.alerts_preview && result.alerts_preview.length > 0 && (
            <div className="pt-2 border-t border-gray-800 space-y-1.5">
              <h5 className="text-xs text-gray-500 uppercase">Alert Preview</h5>
              {result.alerts_preview.map((alert) => (
                <div key={alert.alert_id} className="rounded bg-gray-800/50 px-2 py-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-blue-300">{alert.alert_id}</span>
                    <span className="text-xs text-gray-300">{alert.alert_type}</span>
                    <span className="text-xs font-semibold text-gray-200">{alert.score}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge size="sm" variant={alert.queue === 'soc_malware' ? 'danger' : 'warning'}>{alert.queue.replace('soc_', '')}</Badge>
                    <Badge size="sm" variant={alert.confidence === 'high' ? 'danger' : alert.confidence === 'medium' ? 'warning' : 'muted'}>{alert.confidence}</Badge>
                  </div>
                  <p className="text-[11px] text-gray-400 mt-1 line-clamp-2">{alert.reason}</p>
                </div>
              ))}
            </div>
          )}

          {result.case_id && result.status !== 'running' && (
            <div className="pt-2 border-t border-gray-800 grid grid-cols-2 gap-2">
              <Button size="sm" variant="secondary" onClick={() => onOpenAlerts(result.case_id!)}>
                Open Alerts
              </Button>
              <Button size="sm" variant="secondary" onClick={() => onOpenCase(result.case_id!)}>
                Open Case
              </Button>
            </div>
          )}

          <div className="pt-2">
            {result.status === 'running' ? (
              <Button size="sm" variant="danger" className="w-full" onClick={onCancel}>
                Cancel Scenario
              </Button>
            ) : (
              <Button size="sm" className="w-full" onClick={onRun} disabled={disabled}>
                {result.status === 'not_run' ? 'Run Scenario' : 'Re-run'}
              </Button>
            )}
          </div>
        </div>
      </Card>

      <Card title="Expected Artifacts">
        <div className="flex flex-wrap gap-1">
          {scenario.expected_artifacts.map((artifact) => (
            <Badge key={artifact} variant="muted" size="sm">{artifact}</Badge>
          ))}
        </div>
        <p className="text-[10px] text-gray-600 mt-2">
          {scenario.mode === 'offline'
            ? `Source: samples/scenario_gym/${scenario.file ?? ''}`
            : `Source: live query (${scenario.live?.time_preset ?? '2h'}${scenario.live?.agent_name ? `, agent=${scenario.live.agent_name}` : ''}${scenario.live?.agent_id ? `, agent_id=${scenario.live.agent_id}` : ''})`}
        </p>
      </Card>
    </>
  );
}
