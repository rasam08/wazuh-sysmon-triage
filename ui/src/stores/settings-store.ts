import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { AlertQueue, Profile, TimePreset, RunMode } from '@/types';

/* Section 1: API Endpoint Config */
// Local reference fields for operator convenience only.
// The backend /api runtime is not configured from this client-side store.
export interface ApiEndpointConfig {
  opensearch_url: string;
  index_pattern: string;
  verify_tls: boolean;
  timeout_seconds: number;
  max_results: number;
}

/* Section 2: Default Run Presets */
export interface RunPreset {
  id: string;
  name: string;
  mode: RunMode;
  profile: Profile;
  time_preset: TimePreset;
  queues: AlertQueue[];
  include_dev_queue: boolean;
  min_alert_score: number;
  out_dir: string;
  dry_run: boolean;
  alerts_only: boolean;
  print_stats: boolean;
  verify_tls: boolean | null;
}

/* Section 3: Alert Threshold Tuning */
export interface AlertThresholds {
  high_confidence_min_score: number;
  medium_confidence_min_score: number;
  auto_escalate_score: number;
  auto_suppress_below_score: number;
  max_alerts_per_run: number;
}

/* Section 4: Notification Preferences */
export interface NotificationPrefs {
  toast_duration_ms: number;
  show_success_toasts: boolean;
  show_info_toasts: boolean;
  sound_enabled: boolean;
  desktop_notifications: boolean;
}

/* Section 5: Theme and Display Options */
export type ThemeMode = 'dark' | 'light' | 'system';
export type Density = 'compact' | 'comfortable' | 'spacious';
export type DateFormat = 'iso' | 'locale' | 'relative';

export interface DisplayOptions {
  theme: ThemeMode;
  density: Density;
  date_format: DateFormat;
  monospace_commands: boolean;
  show_process_guids: boolean;
  alerts_page_size: number;
  animations_enabled: boolean;
}

/* Section 6: Allowlist and Suppression Rules */
export interface SuppressionRule {
  id: string;
  name: string;
  field: 'image' | 'command_line' | 'destination_ip' | 'parent_image' | 'process_guid' | 'tags';
  pattern: string;
  enabled: boolean;
  created_at: string;
}

/* Section 7: Export Format Config */
export type ExportFormat = 'json' | 'csv' | 'markdown' | 'ndjson';

export interface ExportConfig {
  default_alert_format: ExportFormat;
  default_report_format: 'markdown' | 'json';
  include_metadata_in_exports: boolean;
  pretty_print_json: boolean;
  csv_delimiter: ',' | ';' | '\t';
  filename_template: string;
}

/* Combined settings state */
interface SettingsState {
  api: ApiEndpointConfig;
  presets: RunPreset[];
  thresholds: AlertThresholds;
  notifications: NotificationPrefs;
  display: DisplayOptions;
  runAllowlistImages: string[];
  suppressionRules: SuppressionRule[];
  exportConfig: ExportConfig;

  // Actions
  setApi: (patch: Partial<ApiEndpointConfig>) => void;
  addPreset: (preset: RunPreset) => void;
  updatePreset: (id: string, patch: Partial<RunPreset>) => void;
  removePreset: (id: string) => void;
  setThresholds: (patch: Partial<AlertThresholds>) => void;
  setNotifications: (patch: Partial<NotificationPrefs>) => void;
  setDisplay: (patch: Partial<DisplayOptions>) => void;
  setRunAllowlistImages: (images: string[]) => void;
  addRunAllowlistImage: (image: string) => void;
  updateRunAllowlistImage: (index: number, image: string) => void;
  removeRunAllowlistImage: (index: number) => void;
  addSuppressionRule: (rule: SuppressionRule) => void;
  updateSuppressionRule: (id: string, patch: Partial<SuppressionRule>) => void;
  removeSuppressionRule: (id: string) => void;
  setExportConfig: (patch: Partial<ExportConfig>) => void;
  resetAll: () => void;
  exportSettings: () => string;
  importSettings: (json: string) => boolean;
}

/* Defaults */
const DEFAULT_API: ApiEndpointConfig = {
  opensearch_url: 'https://localhost:9200',
  index_pattern: 'wazuh-alerts-*',
  verify_tls: true,
  timeout_seconds: 30,
  max_results: 10000,
};

const DEFAULT_THRESHOLDS: AlertThresholds = {
  high_confidence_min_score: 80,
  medium_confidence_min_score: 50,
  auto_escalate_score: 90,
  auto_suppress_below_score: 10,
  max_alerts_per_run: 500,
};

const DEFAULT_NOTIFICATIONS: NotificationPrefs = {
  toast_duration_ms: 4000,
  show_success_toasts: true,
  show_info_toasts: true,
  sound_enabled: false,
  desktop_notifications: false,
};

const DEFAULT_DISPLAY: DisplayOptions = {
  theme: 'dark',
  density: 'comfortable',
  date_format: 'iso',
  monospace_commands: true,
  show_process_guids: false,
  alerts_page_size: 50,
  animations_enabled: true,
};

const DEFAULT_EXPORT: ExportConfig = {
  default_alert_format: 'json',
  default_report_format: 'markdown',
  include_metadata_in_exports: true,
  pretty_print_json: true,
  csv_delimiter: ',',
  filename_template: '{type}-{case_id}-{date}',
};

function normalizePresetOutDir(outDir: string | undefined): string {
  const value = (outDir ?? '').trim();
  if (!value) return '../out';
  if (value === './out' || value === './output' || value === '../output') return '../out';
  return value;
}

function normalizeAllowlistEntry(value: string): string | null {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;
  const parts = trimmed.split(/[\\/]/);
  const basename = parts[parts.length - 1]?.trim();
  if (!basename) return null;
  return basename;
}

function normalizeAllowlistImages(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const item of values) {
    if (typeof item !== 'string') continue;
    const entry = normalizeAllowlistEntry(item);
    if (!entry || seen.has(entry)) continue;
    seen.add(entry);
    normalized.push(entry);
  }
  return normalized;
}

const BUILT_IN_PRESETS: RunPreset[] = [
  {
    id: 'preset-quick-soc',
    name: 'Quick SOC Triage',
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
  },
  {
    id: 'preset-deep-investigation',
    name: 'Deep Investigation',
    mode: 'live',
    profile: 'soc',
    time_preset: '24h',
    queues: ['soc_malware', 'soc_policy', 'soc_info'],
    include_dev_queue: false,
    min_alert_score: 40,
    out_dir: '../out',
    dry_run: false,
    alerts_only: false,
    print_stats: true,
    verify_tls: null,
  },
  {
    id: 'preset-dev-lab',
    name: 'Dev / Lab Mode',
    mode: 'offline',
    profile: 'lab',
    time_preset: '7d',
    queues: ['soc_malware', 'soc_policy', 'soc_dev', 'soc_info'],
    include_dev_queue: true,
    min_alert_score: 0,
    out_dir: '../out',
    dry_run: false,
    alerts_only: false,
    print_stats: true,
    verify_tls: null,
  },
];

function getDefaults() {
  return {
    api: { ...DEFAULT_API },
    presets: [...BUILT_IN_PRESETS],
    thresholds: { ...DEFAULT_THRESHOLDS },
    notifications: { ...DEFAULT_NOTIFICATIONS },
    display: { ...DEFAULT_DISPLAY },
    runAllowlistImages: [] as string[],
    suppressionRules: [] as SuppressionRule[],
    exportConfig: { ...DEFAULT_EXPORT },
  };
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set, get) => ({
      ...getDefaults(),

      setApi: (patch) => set((s) => ({ api: { ...s.api, ...patch } })),

      addPreset: (preset) => set((s) => ({ presets: [...s.presets, preset] })),
      updatePreset: (id, patch) =>
        set((s) => ({ presets: s.presets.map((p) => (p.id === id ? { ...p, ...patch } : p)) })),
      removePreset: (id) => set((s) => ({ presets: s.presets.filter((p) => p.id !== id) })),

      setThresholds: (patch) => set((s) => ({ thresholds: { ...s.thresholds, ...patch } })),
      setNotifications: (patch) => set((s) => ({ notifications: { ...s.notifications, ...patch } })),
      setDisplay: (patch) => set((s) => ({ display: { ...s.display, ...patch } })),
      setRunAllowlistImages: (images) => set({ runAllowlistImages: normalizeAllowlistImages(images) }),
      addRunAllowlistImage: (image) =>
        set((s) => {
          const normalized = normalizeAllowlistEntry(image);
          if (!normalized || s.runAllowlistImages.includes(normalized)) return s;
          return { runAllowlistImages: [...s.runAllowlistImages, normalized] };
        }),
      updateRunAllowlistImage: (index, image) =>
        set((s) => {
          if (index < 0 || index >= s.runAllowlistImages.length) return s;
          const normalized = normalizeAllowlistEntry(image);
          if (!normalized) return s;
          if (
            s.runAllowlistImages.some((entry, entryIndex) => entry === normalized && entryIndex !== index)
          ) {
            return s;
          }
          const next = [...s.runAllowlistImages];
          next[index] = normalized;
          return { runAllowlistImages: next };
        }),
      removeRunAllowlistImage: (index) =>
        set((s) => {
          if (index < 0 || index >= s.runAllowlistImages.length) return s;
          return { runAllowlistImages: s.runAllowlistImages.filter((_, entryIndex) => entryIndex !== index) };
        }),

      addSuppressionRule: (rule) => set((s) => ({ suppressionRules: [...s.suppressionRules, rule] })),
      updateSuppressionRule: (id, patch) =>
        set((s) => ({
          suppressionRules: s.suppressionRules.map((r) => (r.id === id ? { ...r, ...patch } : r)),
        })),
      removeSuppressionRule: (id) =>
        set((s) => ({ suppressionRules: s.suppressionRules.filter((r) => r.id !== id) })),

      setExportConfig: (patch) => set((s) => ({ exportConfig: { ...s.exportConfig, ...patch } })),

      resetAll: () => set(getDefaults()),

      exportSettings: () => {
        const s = get();
        return JSON.stringify({
          api: s.api,
          presets: s.presets,
          thresholds: s.thresholds,
          notifications: s.notifications,
          display: s.display,
          runAllowlistImages: s.runAllowlistImages,
          suppressionRules: s.suppressionRules,
          exportConfig: s.exportConfig,
        }, null, 2);
      },

      importSettings: (json: string) => {
        try {
          const data = JSON.parse(json);
          if (!data || typeof data !== 'object' || Array.isArray(data)) return false;

          // Validate api shape: only accept known string/number/boolean keys
          const safeApi = data.api && typeof data.api === 'object' && !Array.isArray(data.api)
            ? {
                ...DEFAULT_API,
                ...(typeof data.api.opensearch_url === 'string' && { opensearch_url: data.api.opensearch_url }),
                ...(typeof data.api.index_pattern === 'string' && { index_pattern: data.api.index_pattern }),
                ...(typeof data.api.verify_tls === 'boolean' && { verify_tls: data.api.verify_tls }),
                ...(typeof data.api.timeout_seconds === 'number' && { timeout_seconds: Math.max(1, Math.min(300, data.api.timeout_seconds)) }),
                ...(typeof data.api.max_results === 'number' && { max_results: Math.max(100, Math.min(100000, data.api.max_results)) }),
              }
            : undefined;

          // Validate presets: must be an array of objects with required fields
          const safePresets = Array.isArray(data.presets)
            ? data.presets.filter(
                (p: unknown): p is RunPreset =>
                  !!p && typeof p === 'object' && !Array.isArray(p) &&
                  typeof (p as Record<string, unknown>).id === 'string' &&
                  typeof (p as Record<string, unknown>).name === 'string' &&
                  typeof (p as Record<string, unknown>).mode === 'string' &&
                  Array.isArray((p as Record<string, unknown>).queues),
              ).map((p: RunPreset) => ({
                ...p,
                out_dir: normalizePresetOutDir(p.out_dir),
              }))
            : undefined;

          // Validate thresholds: only accept numeric keys in range
          const safeThresholds = data.thresholds && typeof data.thresholds === 'object' && !Array.isArray(data.thresholds)
            ? {
                ...DEFAULT_THRESHOLDS,
                ...Object.fromEntries(
                  Object.entries(data.thresholds as Record<string, unknown>).filter(
                    ([k, v]) => k in DEFAULT_THRESHOLDS && typeof v === 'number' && Number.isFinite(v),
                  ),
                ),
              }
            : undefined;

          // Validate notifications: only accept known boolean/number keys
          const safeNotifications = data.notifications && typeof data.notifications === 'object' && !Array.isArray(data.notifications)
            ? {
                ...DEFAULT_NOTIFICATIONS,
                ...(typeof data.notifications.toast_duration_ms === 'number' && { toast_duration_ms: Math.max(500, Math.min(30000, data.notifications.toast_duration_ms)) }),
                ...(typeof data.notifications.show_success_toasts === 'boolean' && { show_success_toasts: data.notifications.show_success_toasts }),
                ...(typeof data.notifications.show_info_toasts === 'boolean' && { show_info_toasts: data.notifications.show_info_toasts }),
                ...(typeof data.notifications.sound_enabled === 'boolean' && { sound_enabled: data.notifications.sound_enabled }),
                ...(typeof data.notifications.desktop_notifications === 'boolean' && { desktop_notifications: data.notifications.desktop_notifications }),
              }
            : undefined;

          // Validate display: only accept known keys with correct types
          const VALID_THEMES = new Set(['dark', 'light', 'system']);
          const VALID_DENSITIES = new Set(['compact', 'comfortable', 'spacious']);
          const VALID_DATE_FORMATS = new Set(['iso', 'locale', 'relative']);
          const safeDisplay = data.display && typeof data.display === 'object' && !Array.isArray(data.display)
            ? {
                ...DEFAULT_DISPLAY,
                ...(VALID_THEMES.has(data.display.theme) && { theme: data.display.theme }),
                ...(VALID_DENSITIES.has(data.display.density) && { density: data.display.density }),
                ...(VALID_DATE_FORMATS.has(data.display.date_format) && { date_format: data.display.date_format }),
                ...(typeof data.display.monospace_commands === 'boolean' && { monospace_commands: data.display.monospace_commands }),
                ...(typeof data.display.show_process_guids === 'boolean' && { show_process_guids: data.display.show_process_guids }),
                ...(typeof data.display.alerts_page_size === 'number' && { alerts_page_size: Math.max(10, Math.min(500, data.display.alerts_page_size)) }),
                ...(typeof data.display.animations_enabled === 'boolean' && { animations_enabled: data.display.animations_enabled }),
              }
            : undefined;

          const safeRunAllowlistImages = Object.prototype.hasOwnProperty.call(data, 'runAllowlistImages')
            ? normalizeAllowlistImages(data.runAllowlistImages)
            : undefined;

          // Validate suppression rules: must be array of objects with required fields
          const safeSuppression = Array.isArray(data.suppressionRules)
            ? data.suppressionRules.filter(
                (r: unknown): r is SuppressionRule =>
                  !!r && typeof r === 'object' && !Array.isArray(r) &&
                  typeof (r as Record<string, unknown>).id === 'string' &&
                  typeof (r as Record<string, unknown>).name === 'string' &&
                  typeof (r as Record<string, unknown>).field === 'string' &&
                  typeof (r as Record<string, unknown>).pattern === 'string',
              )
            : undefined;

          // Validate export config: only accept known keys with correct types
          const VALID_ALERT_FORMATS = new Set(['json', 'csv', 'markdown', 'ndjson']);
          const VALID_REPORT_FORMATS = new Set(['markdown', 'json']);
          const VALID_DELIMITERS = new Set([',', ';', '\t']);
          const safeExportConfig = data.exportConfig && typeof data.exportConfig === 'object' && !Array.isArray(data.exportConfig)
            ? {
                ...DEFAULT_EXPORT,
                ...(VALID_ALERT_FORMATS.has(data.exportConfig.default_alert_format) && { default_alert_format: data.exportConfig.default_alert_format }),
                ...(VALID_REPORT_FORMATS.has(data.exportConfig.default_report_format) && { default_report_format: data.exportConfig.default_report_format }),
                ...(typeof data.exportConfig.include_metadata_in_exports === 'boolean' && { include_metadata_in_exports: data.exportConfig.include_metadata_in_exports }),
                ...(typeof data.exportConfig.pretty_print_json === 'boolean' && { pretty_print_json: data.exportConfig.pretty_print_json }),
                ...(VALID_DELIMITERS.has(data.exportConfig.csv_delimiter) && { csv_delimiter: data.exportConfig.csv_delimiter }),
                ...(typeof data.exportConfig.filename_template === 'string' && { filename_template: data.exportConfig.filename_template.slice(0, 200) }),
              }
            : undefined;

          set({
            ...(safeApi && { api: safeApi }),
            ...(safePresets && { presets: safePresets }),
            ...(safeThresholds && { thresholds: safeThresholds }),
            ...(safeNotifications && { notifications: safeNotifications }),
            ...(safeDisplay && { display: safeDisplay }),
            ...(safeRunAllowlistImages !== undefined && { runAllowlistImages: safeRunAllowlistImages }),
            ...(safeSuppression && { suppressionRules: safeSuppression }),
            ...(safeExportConfig && { exportConfig: safeExportConfig }),
          });
          return true;
        } catch {
          return false;
        }
      },
    }),
    {
      name: 'wst-settings',
      version: 3,
      migrate: (persistedState) => {
        if (!persistedState || typeof persistedState !== 'object') return persistedState;
        const state = persistedState as { presets?: RunPreset[]; runAllowlistImages?: unknown };
        const migratedAllowlist = normalizeAllowlistImages(state.runAllowlistImages);
        if (!Array.isArray(state.presets)) {
          return {
            ...persistedState,
            runAllowlistImages: migratedAllowlist,
          };
        }
        return {
          ...persistedState,
          runAllowlistImages: migratedAllowlist,
          presets: state.presets.map((preset) => ({
            ...preset,
            out_dir: normalizePresetOutDir(preset.out_dir),
          })),
        };
      },
    },
  ),
);
