import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Card, SuccessCheck, CopiedIcon } from '@/components';
import { useRunsStore, useToastStore, useSettingsStore } from '@/stores';
import type { RunParams, AlertQueue, Profile, TimePreset, RunMode } from '@/types';
import type { RunPreset } from '@/stores/settings-store';
import { copyToClipboard } from '@/utils/exports';
import { fetchRunPreview, type RunPreview } from '@/data/api';
import { useCopyFeedback } from '@/hooks/useCopyFeedback';

const QUEUES: AlertQueue[] = ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'];
const PROFILES: Profile[] = ['soc', 'dev', 'lab'];
const TIME_PRESETS: { value: TimePreset; label: string }[] = [
  { value: '15m', label: '15 min' },
  { value: '2h', label: '2 hours' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: 'today', label: 'Today' },
  { value: 'yesterday', label: 'Yesterday' },
  { value: 'custom', label: 'Custom' },
];

interface PreviewState {
  preview: RunPreview;
  generatedAt: string;
  validationErrors: string[];
}

function generateCaseId() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `CASE-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}-${String(Math.floor(Math.random() * 999) + 1).padStart(3, '0')}`;
}

export default function NewRunScreen() {
  const navigate = useNavigate();
  const submitRun = useRunsStore((s) => s.submitRun);
  const selectedRunId = useRunsStore((s) => s.selectedRunId);
  const runs = useRunsStore((s) => s.runs);
  const addToast = useToastStore((s) => s.addToast);
  const { presets, addPreset, runAllowlistImages } = useSettingsStore();

  const [mode, setMode] = useState<RunMode>('live');
  const [timePreset, setTimePreset] = useState<TimePreset>('2h');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [agentName, setAgentName] = useState('');
  const [agentId, setAgentId] = useState('');
  const [inputFile, setInputFile] = useState('');
  const [profile, setProfile] = useState<Profile>('soc');
  const [queues, setQueues] = useState<AlertQueue[]>(['soc_malware', 'soc_policy']);
  const [includeDevQueue, setIncludeDevQueue] = useState(false);
  const [minScore, setMinScore] = useState(70);
  const [outDir, setOutDir] = useState('../out');
  const [caseId, setCaseId] = useState(generateCaseId);
  const [dryRun, setDryRun] = useState(false);
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [printStats, setPrintStats] = useState(true);
  const [verifyTls, setVerifyTls] = useState<boolean | undefined>(undefined);
  const [running, setRunning] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [preview, setPreview] = useState<PreviewState | null>(null);
  const [showSuccess, setShowSuccess] = useState(false);
  const { copy: copyCli, copied: copiedCli } = useCopyFeedback();
  const { copy: copyJson, copied: copiedJson } = useCopyFeedback();

  const selectedRun = useMemo(
    () => runs.find((r) => r.id === selectedRunId) ?? null,
    [runs, selectedRunId],
  );

  const buildParams = (): RunParams => ({
    mode,
    profile,
    time_preset: timePreset,
    start: start || undefined,
    end: end || undefined,
    agent_name: agentName || undefined,
    agent_id: agentId || undefined,
    input_file: inputFile || undefined,
    queues,
    include_dev_queue: includeDevQueue,
    min_alert_score: minScore,
    out_dir: outDir,
    case_id: caseId,
    dry_run: dryRun,
    alerts_only: alertsOnly,
    print_stats: printStats,
    verify_tls: verifyTls,
    allowlist_images: runAllowlistImages,
  });

  const loadPreset = (preset: RunPreset) => {
    setMode(preset.mode);
    setProfile(preset.profile);
    setTimePreset(preset.time_preset);
    setQueues([...preset.queues]);
    setIncludeDevQueue(preset.include_dev_queue);
    setMinScore(preset.min_alert_score);
    setOutDir(
      preset.out_dir === './out' || preset.out_dir === './output' || preset.out_dir === '../output'
        ? '../out'
        : preset.out_dir,
    );
    setDryRun(preset.dry_run);
    setAlertsOnly(preset.alerts_only);
    setPrintStats(preset.print_stats);
    setVerifyTls(preset.verify_tls === null ? undefined : preset.verify_tls);
    setPreview(null);
    addToast('info', `Preset "${preset.name}" loaded`);
  };

  const saveAsPreset = () => {
    const name = prompt('Preset name:');
    if (!name?.trim()) return;
    const preset: RunPreset = {
      id: `preset-${crypto.randomUUID().slice(0, 8)}`,
      name: name.trim(),
      mode,
      profile,
      time_preset: timePreset,
      queues: [...queues],
      include_dev_queue: includeDevQueue,
      min_alert_score: minScore,
      out_dir: outDir,
      dry_run: dryRun,
      alerts_only: alertsOnly,
      print_stats: printStats,
      verify_tls: verifyTls ?? null,
    };
    addPreset(preset);
    addToast('success', `Preset "${preset.name}" saved`);
  };

  const toggleQueue = (queue: AlertQueue) => {
    setQueues((prev) => (prev.includes(queue) ? prev.filter((x) => x !== queue) : [...prev, queue]));
  };

  const validate = (): string[] => {
    const errs: string[] = [];
    if (!caseId.trim()) errs.push('Case ID is required');
    if (!outDir.trim()) errs.push('Output directory is required');
    if (mode === 'offline' && !inputFile.trim()) errs.push('Input file is required in offline mode');
    if (timePreset === 'custom' && (!start || !end)) errs.push('Start and end times required for custom range');
    if (queues.length === 0) errs.push('At least one queue must be selected');
    return errs;
  };

  const isValid = useMemo(
    () => validate().length === 0,
    [caseId, outDir, mode, inputFile, timePreset, start, end, queues],
  );

  const handleRun = async () => {
    const errs = validate();
    if (errs.length) {
      setErrors(errs);
      return;
    }
    if (dryRun) {
      await handlePreview();
      addToast('info', 'Dry run is preview-only; no run was started');
      return;
    }
    setErrors([]);
    setRunning(true);

    const params = buildParams();
    try {
      const runId = await submitRun(params);
      addToast('success', `Run queued: ${caseId}`);
      setShowSuccess(true);
      setTimeout(() => {
        setShowSuccess(false);
        navigate(`/runs?selected=${runId}`);
      }, 1200);
    } catch (e) {
      addToast('error', `Run failed: ${(e as Error).message}`);
    } finally {
      setRunning(false);
    }
  };

  const handlePreview = async () => {
    const params = buildParams();
    const validationErrors = validate();
    try {
      const serverPreview = await fetchRunPreview(params);
      setPreview({
        preview: serverPreview,
        generatedAt: new Date().toISOString(),
        validationErrors,
      });
      if (validationErrors.length || serverPreview.warnings.length) {
        setErrors(validationErrors);
        addToast('info', 'Preview generated with warnings');
      } else {
        addToast('info', 'Preview generated');
      }
    } catch (e) {
      addToast('error', `Failed to generate preview: ${(e as Error).message}`);
    }
  };

  const handleReset = () => {
    setMode('live');
    setTimePreset('2h');
    setStart('');
    setEnd('');
    setAgentName('');
    setAgentId('');
    setInputFile('');
    setProfile('soc');
    setQueues(['soc_malware', 'soc_policy']);
    setIncludeDevQueue(false);
    setMinScore(70);
    setOutDir('../out');
    setCaseId(generateCaseId());
    setDryRun(false);
    setAlertsOnly(false);
    setPrintStats(true);
    setVerifyTls(undefined);
    setErrors([]);
    setPreview(null);
    addToast('info', 'Form reset to defaults');
  };

  const stages = ['fetch', 'normalize', 'correlate', 'detect', 'render'];
  const previewCommand = preview?.preview.command ?? '';

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">New Triage Run</h1>
        <p className="text-sm text-gray-500 mt-1">Configure and trigger a triage run</p>
      </div>

      {errors.length > 0 && (
        <div className="bg-red-950/40 border border-red-800/50 rounded-lg p-3">
          <p className="text-xs font-semibold text-red-300 mb-1">Please fix the following:</p>
          <ul className="list-disc list-inside text-xs text-red-400 space-y-0.5">
            {errors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      {running && (
        <Card title="Pipeline Progress">
          <div className="flex gap-2">
            {stages.map((stage) => {
              const current = selectedRun?.current_stage;
              const idx = stages.indexOf(stage);
              const currentIdx = current ? stages.indexOf(current) : -1;
              const done = idx < currentIdx;
              const active = idx === currentIdx;
              return (
                <div
                  key={stage}
                  className={`flex-1 rounded px-3 py-2 text-center text-xs font-medium transition-colors
                  ${done ? 'bg-emerald-900/50 text-emerald-300' : active ? 'bg-blue-900/50 text-blue-300 animate-pulse' : 'bg-gray-800 text-gray-500'}`}
                >
                  {stage}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      <Card title="Run Mode">
        <div className="flex gap-2">
          {(['live', 'offline'] as RunMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors
                ${mode === m ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
            >
              {m.charAt(0).toUpperCase() + m.slice(1)}
            </button>
          ))}
        </div>
      </Card>

      <Card title="Time Window">
        <div className="flex flex-wrap gap-2 mb-4">
          {TIME_PRESETS.map((tp) => (
            <button
              key={tp.value}
              onClick={() => setTimePreset(tp.value)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors
                ${timePreset === tp.value ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
            >
              {tp.label}
            </button>
          ))}
        </div>
        {timePreset === 'custom' && (
          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs text-gray-500">Start</span>
              <input
                type="datetime-local"
                value={start}
                onChange={(e) => setStart(e.target.value)}
                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="text-xs text-gray-500">End</span>
              <input
                type="datetime-local"
                value={end}
                onChange={(e) => setEnd(e.target.value)}
                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
              />
            </label>
          </div>
        )}
      </Card>

      <Card title="Source Configuration">
        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="text-xs text-gray-500">Agent Name</span>
            <input
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              placeholder="win-workstation-01"
              className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-500">Agent ID</span>
            <input
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="001"
              className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        {mode === 'offline' && (
          <label className="block mt-4">
            <span className="text-xs text-gray-500">Input File (.ndjson)</span>
            <input
              value={inputFile}
              onChange={(e) => setInputFile(e.target.value)}
              placeholder="samples/incident_001/raw_hits.ndjson"
              className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            />
            {!inputFile && <p className="text-xs text-red-400 mt-1">Required in offline mode</p>}
          </label>
        )}
      </Card>

      <Card title="Detection Profile">
        <div className="space-y-4">
          <div>
            <span className="text-xs text-gray-500 block mb-2">Profile</span>
            <div className="flex gap-2">
              {PROFILES.map((p) => (
                <button
                  key={p}
                  onClick={() => setProfile(p)}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition-colors
                    ${profile === p ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
          <div>
            <span className="text-xs text-gray-500 block mb-2">Queues</span>
            <div className="flex flex-wrap gap-2">
              {QUEUES.map((queue) => (
                <button
                  key={queue}
                  onClick={() => toggleQueue(queue)}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition-colors
                    ${queues.includes(queue) ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
                >
                  {queue}
                </button>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={includeDevQueue}
              onChange={(e) => setIncludeDevQueue(e.target.checked)}
              className="rounded bg-gray-800 border-gray-600 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-300">Include Dev Queue</span>
          </label>
        </div>
      </Card>

      <Card title="Output Settings">
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-gray-500">Min Alert Score</span>
              <span className="text-xs text-gray-400 tabular-nums">{minScore}</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-full accent-blue-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs text-gray-500">Output Directory</span>
              <input
                value={outDir}
                readOnly
                className="mt-1 block w-full bg-gray-800/60 border border-gray-700 rounded px-3 py-2 text-sm text-gray-400 focus:outline-none cursor-not-allowed"
              />
              <p className="text-xs text-gray-600 mt-1">Managed by server API output root.</p>
            </label>
            <label className="block">
              <span className="text-xs text-gray-500">Case ID</span>
              <input
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                pattern="^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$"
                className={`mt-1 block w-full bg-gray-800 border rounded px-3 py-2 text-sm text-gray-200 focus:outline-none ${
                  caseId && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/.test(caseId)
                    ? 'border-red-500 focus:border-red-500'
                    : 'border-gray-700 focus:border-blue-500'
                }`}
              />
              {caseId && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/.test(caseId) ? (
                <p className="text-xs text-red-400 mt-1">Must start with alphanumeric, contain only [A-Za-z0-9._-], max 81 chars</p>
              ) : (
                <p className="text-xs text-gray-600 mt-1">Preview: {caseId}</p>
              )}
            </label>
          </div>
        </div>
      </Card>

      <Card title="Run-Time Allowlist">
        <div className="space-y-2">
          <p className="text-xs text-gray-500">
            {runAllowlistImages.length === 0
              ? 'No custom allowlist images configured. Defaults from backend/config still apply.'
              : `${runAllowlistImages.length} custom allowlist image entries will be passed to this run.`}
          </p>
          {runAllowlistImages.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {runAllowlistImages.map((entry) => (
                <span key={entry} className="px-2 py-0.5 text-xs rounded bg-gray-800 text-gray-300 border border-gray-700 font-mono">
                  {entry}
                </span>
              ))}
            </div>
          )}
          <div>
            <Button size="sm" variant="ghost" onClick={() => navigate('/settings')}>
              Edit Allowlist in Settings
            </Button>
          </div>
        </div>
      </Card>

      <Card title="Options">
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: 'Dry Run Query', checked: dryRun, set: setDryRun },
            { label: 'Alerts Only', checked: alertsOnly, set: setAlertsOnly },
            { label: 'Print Stats', checked: printStats, set: setPrintStats },
          ].map(({ label, checked, set }) => (
            <label key={label} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={checked}
                onChange={(e) => set(e.target.checked)}
                className="rounded bg-gray-800 border-gray-600 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-300">{label}</span>
            </label>
          ))}
        </div>
        <div className="mt-4">
          <span className="text-xs text-gray-500 block mb-2">TLS Mode</span>
          <div className="flex gap-2">
            {[
              { key: 'auto', label: 'Auto', value: undefined as boolean | undefined },
              { key: 'verify', label: 'Verify TLS', value: true as boolean | undefined },
              { key: 'insecure', label: 'No Verify', value: false as boolean | undefined },
            ].map((item) => {
              const active = verifyTls === item.value;
              return (
                <button
                  key={item.key}
                  onClick={() => setVerifyTls(item.value)}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition-colors
                    ${active ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
                >
                  {item.label}
                </button>
              );
            })}
          </div>
          <p className="text-xs text-gray-500 mt-2">
            Auto mode follows CLI environment/profile defaults (lab profile resolves to no-verify).
          </p>
        </div>
      </Card>

      {presets.length > 0 && (
        <Card title="Quick Presets">
          <div className="flex flex-wrap gap-2">
            {presets.map((preset) => (
              <button
                key={preset.id}
                onClick={() => loadPreset(preset)}
                className="px-3 py-2 rounded-md text-sm font-medium bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors border border-gray-700"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </Card>
      )}

      {preview && (
        <Card
          title="Query Preview"
          actions={
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="ghost"
                onClick={async () => {
                  const ok = await copyCli(previewCommand);
                  if (!ok) addToast('error', 'Copy failed');
                }}
              >
                {copiedCli ? <CopiedIcon /> : 'Copy CLI'}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={async () => {
                  const ok = await copyJson(JSON.stringify(preview.preview.params, null, 2));
                  if (!ok) addToast('error', 'Copy failed');
                }}
              >
                {copiedJson ? <CopiedIcon /> : 'Copy JSON'}
              </Button>
            </div>
          }
        >
          <div className="space-y-3">
            <p className="text-xs text-gray-500">
              Generated at {new Date(preview.generatedAt).toLocaleString()}
            </p>
            {(preview.validationErrors.length > 0 || preview.preview.warnings.length > 0) && (
              <div className="bg-yellow-950/30 border border-yellow-800/50 rounded p-2">
                <p className="text-xs text-yellow-300 font-semibold mb-1">Validation warnings:</p>
                <ul className="list-disc list-inside text-xs text-yellow-400 space-y-0.5">
                  {[...preview.validationErrors, ...preview.preview.warnings].map((err, idx) => <li key={idx}>{err}</li>)}
                </ul>
              </div>
            )}
            <div>
              <p className="text-xs text-gray-500 mb-1">CLI Command</p>
              <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-xs text-gray-300 overflow-x-auto">{previewCommand}</pre>
            </div>
            <div>
              <p className="text-xs text-gray-500 mb-1">Resolved Parameters</p>
              <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-xs text-gray-300 max-h-56 overflow-auto">{JSON.stringify(preview.preview.params, null, 2)}</pre>
            </div>
          </div>
        </Card>
      )}

      {showSuccess && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-950/70 backdrop-blur-sm">
          <SuccessCheck size={72} label={`Run ${caseId} completed`} />
        </div>
      )}

      <div className="flex items-center gap-3 pt-2">
        <Button onClick={handleRun} loading={running} disabled={!isValid || running}>
          {running ? 'Running...' : 'Run Triage'}
        </Button>
        <Button variant="secondary" onClick={handlePreview} disabled={running}>
          Preview Query
        </Button>
        <Button variant="secondary" onClick={saveAsPreset}>
          Save as Preset
        </Button>
        <Button variant="ghost" onClick={handleReset} disabled={running}>
          Reset
        </Button>
      </div>
    </div>
  );
}
