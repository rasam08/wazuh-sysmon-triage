import React, { useEffect, useState, useRef } from 'react';
import { Badge, Button, Card, useConfirmModal } from '@/components';
import { useSettingsStore, useToastStore } from '@/stores';
import { fetchHealth } from '@/data/api';
import type { HealthStatus } from '@/types';
import type {
  ApiEndpointConfig, AlertThresholds, NotificationPrefs, DisplayOptions,
  ExportConfig, SuppressionRule, RunPreset, ThemeMode, Density, DateFormat, ExportFormat,
} from '@/stores/settings-store';

/* Section nav items */
const SECTIONS = [
  { id: 'api', label: 'API Endpoint' },
  { id: 'presets', label: 'Run Presets' },
  { id: 'thresholds', label: 'Alert Thresholds' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'display', label: 'Theme & Display' },
  { id: 'allowlist', label: 'Run Allowlist' },
  { id: 'suppression', label: 'Suppression Rules' },
  { id: 'export', label: 'Export Config' },
] as const;

export default function SettingsScreen() {
  const [activeSection, setActiveSection] = useState('api');
  const addToast = useToastStore((s) => s.addToast);
  const { resetAll, exportSettings, importSettings } = useSettingsStore();
  const { modal: confirmModal, confirm } = useConfirmModal();
  const fileRef = useRef<HTMLInputElement>(null);

  const handleExport = () => {
    const json = exportSettings();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'wst-settings.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addToast('success', 'Settings exported');
  };

  const handleImport = () => fileRef.current?.click();

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const ok = importSettings(reader.result as string);
      addToast(ok ? 'success' : 'error', ok ? 'Settings imported' : 'Invalid settings file');
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleReset = async () => {
    const ok = await confirm(
      'Reset All Settings',
      'This will revert every setting to its factory default. This action cannot be undone.',
    );
    if (!ok) return;
    resetAll();
    addToast('info', 'Settings reset to defaults');
  };

  return (
    <>
    <div className="flex gap-6 h-[calc(100vh-8rem)]">
      {/* Sidebar nav */}
      <nav className="w-52 flex-shrink-0 space-y-1">
        <h2 className="text-lg font-bold text-gray-100 mb-4">Settings</h2>
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveSection(s.id)}
            className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium transition-colors
              ${activeSection === s.id
                ? 'bg-gray-800 text-white border-l-2 border-blue-500'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'}`}
          >
            {s.label}
          </button>
        ))}

        <div className="pt-6 space-y-2">
          <input type="file" ref={fileRef} accept=".json" onChange={handleFileChange} className="hidden" />
          <Button variant="secondary" size="sm" className="w-full" onClick={handleExport}>Export Settings</Button>
          <Button variant="secondary" size="sm" className="w-full" onClick={handleImport}>Import Settings</Button>
          <Button variant="danger" size="sm" className="w-full" onClick={handleReset}>Reset All</Button>
        </div>
      </nav>

      {/* Content area */}
      <div className="flex-1 overflow-y-auto space-y-6 max-w-3xl">
        {activeSection === 'api' && <ApiSection />}
        {activeSection === 'presets' && <PresetsSection />}
        {activeSection === 'thresholds' && <ThresholdsSection />}
        {activeSection === 'notifications' && <NotificationsSection />}
        {activeSection === 'display' && <DisplaySection />}
        {activeSection === 'allowlist' && <RunAllowlistSection />}
        {activeSection === 'suppression' && <SuppressionSection />}
        {activeSection === 'export' && <ExportSection />}
      </div>
    </div>
    {confirmModal}
    </>
  );
}

/* Section 1: API Endpoint */
function ApiSection() {
  const { api, setApi } = useSettingsStore();
  const addToast = useToastStore((s) => s.addToast);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [testing, setTesting] = useState(false);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const healthBadgeVariant = health?.opensearch_connectivity === 'reachable'
    ? 'success'
    : (health?.opensearch_connectivity === 'unreachable' ? 'danger' : 'muted');

  const checkHealth = async () => {
    setCheckingHealth(true);
    try {
      const payload = await fetchHealth('soc');
      setHealth(payload);
    } catch {
      setHealth({
        checked_at: new Date().toISOString(),
        profile: 'soc',
        opensearch_host: null,
        opensearch_connectivity: 'unknown',
        opensearch_http_status: null,
        tls_mode: 'unknown',
        last_successful_fetch_at: null,
      });
    } finally {
      setCheckingHealth(false);
    }
  };

  useEffect(() => {
    void checkHealth();
  }, []);

  const testConnection = async () => {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(api.opensearch_url);
    } catch {
      addToast('error', 'Invalid OpenSearch URL');
      return;
    }

    setTesting(true);
    try {
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), Math.max(2000, api.timeout_seconds * 1000));

      const response = await fetch(parsedUrl.toString(), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      window.clearTimeout(timeoutId);

      if (response.ok) {
        addToast('success', `Connection OK (${response.status})`);
      } else {
        addToast('error', `Connection failed (${response.status})`);
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown error';
      addToast('error', `Connection error: ${message}`);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card title="API Endpoint Configuration">
      <div className="space-y-4">
        <p className="text-xs text-gray-500">
          Local reference only. These fields do not change the local <code>/api</code> runtime. Runtime values come
          from CLI args and backend config files.
        </p>
        <div className="bg-gray-800/40 border border-gray-700 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">Health Status</span>
            <Badge variant={healthBadgeVariant}>{health?.opensearch_connectivity ?? 'unknown'}</Badge>
          </div>
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>Host</span>
            <span className="text-gray-300">{health?.opensearch_host ?? 'Not configured'}</span>
          </div>
          <Button size="sm" variant="ghost" loading={checkingHealth} onClick={checkHealth}>
            Re-check Health
          </Button>
        </div>
        <Field label="OpenSearch URL">
          <input value={api.opensearch_url} onChange={(e) => setApi({ opensearch_url: e.target.value })} className={inputCls} placeholder="https://localhost:9200" />
        </Field>
        <Field label="Index Pattern">
          <input value={api.index_pattern} onChange={(e) => setApi({ index_pattern: e.target.value })} className={inputCls} placeholder="wazuh-alerts-*" />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Timeout (seconds)">
            <input type="number" value={api.timeout_seconds} onChange={(e) => setApi({ timeout_seconds: +e.target.value })} className={inputCls} min={1} max={300} />
          </Field>
          <Field label="Max Results">
            <input type="number" value={api.max_results} onChange={(e) => setApi({ max_results: +e.target.value })} className={inputCls} min={100} max={100000} />
          </Field>
        </div>
        <Toggle label="Verify TLS" checked={api.verify_tls} onChange={(v) => setApi({ verify_tls: v })} />
        <Button size="sm" loading={testing} onClick={testConnection}>Test URL Reachability</Button>
      </div>
    </Card>
  );
}

/* Section 2: Run Presets */
function PresetsSection() {
  const { presets, addPreset, removePreset } = useSettingsStore();
  const addToast = useToastStore((s) => s.addToast);
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState('');

  const handleCreate = () => {
    if (!newName.trim()) return;
    const preset: RunPreset = {
      id: `preset-${crypto.randomUUID().slice(0, 8)}`,
      name: newName.trim(),
      mode: 'live',
      profile: 'soc',
      time_preset: '2h',
      queues: ['soc_malware', 'soc_policy'],
      include_dev_queue: false,
      min_alert_score: 70,
      out_dir: '../out',
      dry_run: false,
      alerts_only: false,
      print_stats: true,
      verify_tls: null,
    };
    addPreset(preset);
    setNewName('');
    setShowNew(false);
    addToast('success', `Preset "${preset.name}" created`);
  };

  return (
    <Card title="Default Run Presets" actions={<Button size="sm" onClick={() => setShowNew(true)}>Add Preset</Button>}>
      <div className="space-y-3">
        {showNew && (
          <div className="flex gap-2 items-end bg-gray-800 rounded-lg p-3">
            <Field label="Preset Name" className="flex-1">
              <input value={newName} onChange={(e) => setNewName(e.target.value)} className={inputCls} placeholder="My custom preset" autoFocus
                onKeyDown={(e) => { if (e.key === 'Enter') handleCreate(); }} />
            </Field>
            <Button size="sm" onClick={handleCreate}>Create</Button>
            <Button size="sm" variant="ghost" onClick={() => { setShowNew(false); setNewName(''); }}>Cancel</Button>
          </div>
        )}
        {presets.length === 0 ? (
          <p className="text-sm text-gray-500">No presets configured</p>
        ) : presets.map((p) => (
          <div key={p.id} className="flex items-center justify-between bg-gray-800/60 rounded-lg px-4 py-3">
            <div>
              <p className="text-sm font-medium text-gray-200">{p.name}</p>
              <p className="text-xs text-gray-500 mt-0.5">
                {p.mode} | {p.profile} | {p.time_preset} | score&gt;={p.min_alert_score} | {p.queues.length} queues
              </p>
            </div>
            <div className="flex gap-2">
              <Button size="sm" variant="danger" onClick={() => { removePreset(p.id); addToast('info', `Preset "${p.name}" removed`); }}>
                Remove
              </Button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* Section 3: Alert Thresholds */
function ThresholdsSection() {
  const { thresholds, setThresholds } = useSettingsStore();

  return (
    <Card title="Alert Threshold Tuning">
      <div className="space-y-5">
        <SliderField label="High Confidence Min Score" value={thresholds.high_confidence_min_score}
          onChange={(v) => setThresholds({ high_confidence_min_score: v })} min={0} max={100}
          description="Alerts at or above this score are marked high confidence" />
        <SliderField label="Medium Confidence Min Score" value={thresholds.medium_confidence_min_score}
          onChange={(v) => setThresholds({ medium_confidence_min_score: v })} min={0} max={100}
          description="Alerts at or above this score are marked medium confidence" />
        <SliderField label="Auto-Escalate Score" value={thresholds.auto_escalate_score}
          onChange={(v) => setThresholds({ auto_escalate_score: v })} min={0} max={100}
          description="Alerts at or above this score are automatically escalated" />
        <SliderField label="Auto-Suppress Below Score" value={thresholds.auto_suppress_below_score}
          onChange={(v) => setThresholds({ auto_suppress_below_score: v })} min={0} max={100}
          description="Alerts below this score are automatically suppressed" />
        <Field label="Max Alerts Per Run">
          <input type="number" value={thresholds.max_alerts_per_run}
            onChange={(e) => setThresholds({ max_alerts_per_run: +e.target.value })}
            className={inputCls} min={1} max={10000} />
        </Field>
      </div>
    </Card>
  );
}

/* Section 4: Notifications */
function NotificationsSection() {
  const { notifications, setNotifications } = useSettingsStore();

  return (
    <Card title="Notification Preferences">
      <div className="space-y-4">
        <Field label="Toast Duration (ms)">
          <input type="number" value={notifications.toast_duration_ms}
            onChange={(e) => setNotifications({ toast_duration_ms: +e.target.value })}
            className={inputCls} min={1000} max={30000} step={500} />
        </Field>
        <Toggle label="Show Success Toasts" checked={notifications.show_success_toasts}
          onChange={(v) => setNotifications({ show_success_toasts: v })} />
        <Toggle label="Show Info Toasts" checked={notifications.show_info_toasts}
          onChange={(v) => setNotifications({ show_info_toasts: v })} />
        <Toggle label="Sound Effects" checked={notifications.sound_enabled}
          onChange={(v) => setNotifications({ sound_enabled: v })} />
        <Toggle label="Desktop Notifications" checked={notifications.desktop_notifications}
          onChange={(v) => setNotifications({ desktop_notifications: v })}
          description="Requires browser permission" />
      </div>
    </Card>
  );
}

/* Section 5: Theme and Display */
function DisplaySection() {
  const { display, setDisplay } = useSettingsStore();

  return (
    <Card title="Theme & Display Options">
      <div className="space-y-5">
        <Field label="Theme">
          <SegmentedControl
            value={display.theme}
            options={[
              { value: 'dark' as ThemeMode, label: 'Dark' },
              { value: 'light' as ThemeMode, label: 'Light' },
              { value: 'system' as ThemeMode, label: 'System' },
            ]}
            onChange={(v) => setDisplay({ theme: v })}
          />
        </Field>
        <Field label="Density">
          <SegmentedControl
            value={display.density}
            options={[
              { value: 'compact' as Density, label: 'Compact' },
              { value: 'comfortable' as Density, label: 'Comfortable' },
              { value: 'spacious' as Density, label: 'Spacious' },
            ]}
            onChange={(v) => setDisplay({ density: v })}
          />
        </Field>
        <Field label="Date Format">
          <SegmentedControl
            value={display.date_format}
            options={[
              { value: 'iso' as DateFormat, label: 'ISO 8601' },
              { value: 'locale' as DateFormat, label: 'Locale' },
              { value: 'relative' as DateFormat, label: 'Relative' },
            ]}
            onChange={(v) => setDisplay({ date_format: v })}
          />
        </Field>
        <Field label="Alerts Page Size">
          <input type="number" value={display.alerts_page_size}
            onChange={(e) => setDisplay({ alerts_page_size: +e.target.value })}
            className={inputCls} min={10} max={500} step={10} />
        </Field>
        <Toggle label="Monospace Commands" checked={display.monospace_commands}
          onChange={(v) => setDisplay({ monospace_commands: v })}
          description="Display command lines and paths in monospace font" />
        <Toggle label="Show Process GUIDs" checked={display.show_process_guids}
          onChange={(v) => setDisplay({ show_process_guids: v })}
          description="Show raw process GUIDs in alert details" />
        <Toggle label="Animations Enabled" checked={display.animations_enabled}
          onChange={(v) => setDisplay({ animations_enabled: v })} />
      </div>
    </Card>
  );
}

/* Section 6: Run Allowlist */
function RunAllowlistSection() {
  const {
    runAllowlistImages,
    addRunAllowlistImage,
    updateRunAllowlistImage,
    removeRunAllowlistImage,
  } = useSettingsStore();
  const addToast = useToastStore((s) => s.addToast);
  const [newEntry, setNewEntry] = useState('');
  const [drafts, setDrafts] = useState<Record<number, string>>({});

  const handleAdd = () => {
    if (!newEntry.trim()) return;
    addRunAllowlistImage(newEntry);
    setNewEntry('');
    addToast('success', 'Allowlist entry added');
  };

  const handleSave = (index: number) => {
    const draft = drafts[index] ?? runAllowlistImages[index] ?? '';
    if (!draft.trim()) return;
    updateRunAllowlistImage(index, draft);
    setDrafts((state) => {
      const next = { ...state };
      delete next[index];
      return next;
    });
    addToast('success', 'Allowlist entry updated');
  };

  return (
    <Card title="Run-Time Detection Allowlist">
      <div className="space-y-4">
        <p className="text-xs text-gray-500">
          Entries here are passed to the CLI as <code>--allowlist-image</code> on each run from this UI. You can enter
          a service file name (for example <code>chrome.exe</code>) or a full path; entries are normalized to basename.
        </p>
        <div className="flex gap-2">
          <input
            value={newEntry}
            onChange={(e) => setNewEntry(e.target.value)}
            className={inputCls}
            placeholder="Allowed service or file (for example C:\\Program Files\\App\\app.exe)"
            onKeyDown={(e) => { if (e.key === 'Enter') handleAdd(); }}
          />
          <Button size="sm" onClick={handleAdd}>Add</Button>
        </div>
        {runAllowlistImages.length === 0 ? (
          <p className="text-sm text-gray-500">No custom run allowlist entries configured.</p>
        ) : (
          <div className="space-y-2">
            {runAllowlistImages.map((entry, index) => (
              <div key={`${entry}-${index}`} className="flex gap-2 items-center bg-gray-800/60 rounded-lg px-3 py-2">
                <input
                  value={drafts[index] ?? entry}
                  onChange={(e) => setDrafts((state) => ({ ...state, [index]: e.target.value }))}
                  className={`${inputCls} text-xs`}
                />
                <Button size="sm" variant="ghost" onClick={() => handleSave(index)}>Save</Button>
                <Button
                  size="sm"
                  variant="danger"
                  onClick={() => {
                    removeRunAllowlistImage(index);
                    addToast('info', 'Allowlist entry removed');
                  }}
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

/* Section 7: Suppression Rules */
const SUPPRESSION_FIELDS: SuppressionRule['field'][] = ['image', 'command_line', 'destination_ip', 'parent_image', 'process_guid', 'tags'];

function SuppressionSection() {
  const { suppressionRules, addSuppressionRule, updateSuppressionRule, removeSuppressionRule } = useSettingsStore();
  const addToast = useToastStore((s) => s.addToast);
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState('');
  const [newField, setNewField] = useState<SuppressionRule['field']>('image');
  const [newPattern, setNewPattern] = useState('');

  const handleCreate = () => {
    if (!newName.trim() || !newPattern.trim()) return;
    addSuppressionRule({
      id: crypto.randomUUID().slice(0, 8),
      name: newName.trim(),
      field: newField,
      pattern: newPattern.trim(),
      enabled: true,
      created_at: new Date().toISOString(),
    });
    setNewName(''); setNewPattern(''); setNewField('image'); setShowNew(false);
    addToast('success', 'Suppression rule added');
  };

  return (
    <Card title="Suppression Rules" actions={<Button size="sm" onClick={() => setShowNew(true)}>Add Rule</Button>}>
      <div className="space-y-3">
        {showNew && (
          <div className="bg-gray-800 rounded-lg p-3 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Rule Name">
                <input value={newName} onChange={(e) => setNewName(e.target.value)} className={inputCls} placeholder="e.g., Ignore Windows Defender" autoFocus />
              </Field>
              <Field label="Field">
                <select value={newField} onChange={(e) => setNewField(e.target.value as SuppressionRule['field'])} className={selectCls}>
                  {SUPPRESSION_FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
                </select>
              </Field>
            </div>
            <Field label="Pattern (regex or exact match)">
              <input value={newPattern} onChange={(e) => setNewPattern(e.target.value)} className={inputCls}
                placeholder="e.g., C:\\Program Files\\Windows Defender\\*"
                onKeyDown={(e) => { if (e.key === 'Enter') handleCreate(); }} />
            </Field>
            <div className="flex gap-2">
              <Button size="sm" onClick={handleCreate}>Create Rule</Button>
              <Button size="sm" variant="ghost" onClick={() => { setShowNew(false); setNewName(''); setNewPattern(''); }}>Cancel</Button>
            </div>
          </div>
        )}
        {suppressionRules.length === 0 ? (
          <p className="text-sm text-gray-500">No suppression rules configured. Add rules to filter out known-good processes from alerts.</p>
        ) : suppressionRules.map((r) => (
          <div key={r.id} className="flex items-center justify-between bg-gray-800/60 rounded-lg px-4 py-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${r.enabled ? 'bg-emerald-500' : 'bg-gray-600'}`} />
                <p className="text-sm font-medium text-gray-200">{r.name}</p>
              </div>
              <p className="text-xs text-gray-500 mt-0.5 font-mono truncate">{r.field}: {r.pattern}</p>
            </div>
            <div className="flex gap-2 flex-shrink-0">
              <Button size="sm" variant="ghost"
                onClick={() => updateSuppressionRule(r.id, { enabled: !r.enabled })}>
                {r.enabled ? 'Disable' : 'Enable'}
              </Button>
              <Button size="sm" variant="danger" onClick={() => { removeSuppressionRule(r.id); addToast('info', 'Rule removed'); }}>
                Remove
              </Button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* Section 8: Export Config */
function ExportSection() {
  const { exportConfig, setExportConfig } = useSettingsStore();

  return (
    <Card title="Export Format Configuration">
      <div className="space-y-5">
        <Field label="Default Alert Export Format">
          <SegmentedControl
            value={exportConfig.default_alert_format}
            options={[
              { value: 'json' as ExportFormat, label: 'JSON' },
              { value: 'csv' as ExportFormat, label: 'CSV' },
              { value: 'ndjson' as ExportFormat, label: 'NDJSON' },
            ]}
            onChange={(v) => setExportConfig({ default_alert_format: v })}
          />
        </Field>
        <Field label="Default Report Format">
          <SegmentedControl
            value={exportConfig.default_report_format}
            options={[
              { value: 'markdown' as 'markdown', label: 'Markdown' },
              { value: 'json' as 'json', label: 'JSON' },
            ]}
            onChange={(v) => setExportConfig({ default_report_format: v })}
          />
        </Field>
        <Field label="CSV Delimiter">
          <SegmentedControl
            value={exportConfig.csv_delimiter}
            options={[
              { value: ',' as const, label: 'Comma' },
              { value: ';' as const, label: 'Semicolon' },
              { value: '\t' as const, label: 'Tab' },
            ]}
            onChange={(v) => setExportConfig({ csv_delimiter: v })}
          />
        </Field>
        <Field label="Filename Template">
          <input value={exportConfig.filename_template}
            onChange={(e) => setExportConfig({ filename_template: e.target.value })}
            className={inputCls} placeholder="{type}-{case_id}-{date}" />
          <p className="text-xs text-gray-600 mt-1">Variables: {'{type}'}, {'{case_id}'}, {'{date}'}, {'{timestamp}'}</p>
        </Field>
        <Toggle label="Include Metadata in Exports" checked={exportConfig.include_metadata_in_exports}
          onChange={(v) => setExportConfig({ include_metadata_in_exports: v })} />
        <Toggle label="Pretty Print JSON" checked={exportConfig.pretty_print_json}
          onChange={(v) => setExportConfig({ pretty_print_json: v })} />
      </div>
    </Card>
  );
}

/* Reusable form primitives */
const inputCls = 'block w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500/30';
const selectCls = `${inputCls} appearance-none`;

function Field({ label, children, className = '' }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <label className={`block ${className}`}>
      <span className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-1.5 block">{label}</span>
      {children}
    </label>
  );
}

function Toggle({ label, checked, onChange, description }: {
  label: string; checked: boolean; onChange: (v: boolean) => void; description?: string;
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group">
      <div className="relative flex-shrink-0 mt-0.5">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="sr-only peer" />
        <div className="w-9 h-5 bg-gray-700 rounded-full peer-checked:bg-blue-600 transition-colors" />
        <div className="absolute left-0.5 top-0.5 w-4 h-4 bg-gray-300 rounded-full transition-transform peer-checked:translate-x-4 peer-checked:bg-white" />
      </div>
      <div>
        <span className="text-sm text-gray-200 group-hover:text-white transition-colors">{label}</span>
        {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
      </div>
    </label>
  );
}

function SliderField({ label, value, onChange, min, max, description }: {
  label: string; value: number; onChange: (v: number) => void; min: number; max: number; description?: string;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">{label}</span>
        <span className="text-sm font-mono text-gray-200 tabular-nums bg-gray-800 px-2 py-0.5 rounded">{value}</span>
      </div>
      <input type="range" min={min} max={max} value={value} onChange={(e) => onChange(+e.target.value)}
        className="w-full accent-blue-500 h-1.5" />
      {description && <p className="text-xs text-gray-500 mt-1">{description}</p>}
    </div>
  );
}

function SegmentedControl<T extends string>({ value, options, onChange }: {
  value: T; options: { value: T; label: string }[]; onChange: (v: T) => void;
}) {
  return (
    <div className="flex gap-1 bg-gray-800/50 rounded-lg p-1">
      {options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
            ${value === opt.value
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/50'}`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
