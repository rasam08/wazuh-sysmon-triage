import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type {
  Run, RunParams, Case, Alert, AlertFilters, AlertSort,
} from '@/types';
import {
  DEFAULT_FILTERS,
  DEFAULT_SORT,
  matchesSuppressionRule,
  scoreToConfidence,
} from '@/data/parsers';
import * as api from '@/data/api';
import { useSettingsStore } from './settings-store';

export { useSettingsStore };
export type { RunPreset, SettingsState } from './settings-store';

function applyAlertPolicies(alerts: Alert[]): Alert[] {
  const settings = useSettingsStore.getState();
  const enabledRules = settings.suppressionRules.filter((r) => r.enabled);

  let nextAlerts = alerts
    .filter((alert) => alert.score >= settings.thresholds.auto_suppress_below_score)
    .filter((alert) => !enabledRules.some((rule) => matchesSuppressionRule(alert, rule)))
    .map((alert) => ({
      ...alert,
      confidence: scoreToConfidence(alert.score, settings.thresholds),
      tags: alert.score >= settings.thresholds.auto_escalate_score
        ? Array.from(new Set([...(alert.tags ?? []), 'auto_escalated']))
        : alert.tags,
    }));

  if (nextAlerts.length > settings.thresholds.max_alerts_per_run) {
    nextAlerts = [...nextAlerts]
      .sort((a, b) => b.score - a.score)
      .slice(0, settings.thresholds.max_alerts_per_run);
  }
  return nextAlerts;
}

function deriveStatsFromAlerts(base: Case['stats'], alerts: Alert[]): Case['stats'] {
  const queues: Record<string, number> = {};
  const categories: Record<string, number> = {};
  const confidenceDistribution: Record<string, number> = {};
  const suspiciousIps = new Set<string>();

  for (const alert of alerts) {
    queues[alert.queue] = (queues[alert.queue] ?? 0) + 1;
    categories[alert.category] = (categories[alert.category] ?? 0) + 1;
    confidenceDistribution[alert.confidence] = (confidenceDistribution[alert.confidence] ?? 0) + 1;
    if (alert.destination_ip) suspiciousIps.add(alert.destination_ip);
  }

  return {
    ...base,
    alerts_generated: alerts.length,
    queues,
    categories,
    confidence_distribution: confidenceDistribution,
    suspicious_destinations: suspiciousIps.size,
  };
}

/* ═══════════════════════════════════════════
   Runs Store
   ═══════════════════════════════════════════ */
interface RunsState {
  runs: Run[];
  selectedRunId: string | null;
  loading: boolean;
  error: string | null;
  fetchRuns: () => Promise<void>;
  selectRun: (id: string | null) => void;
  startRun: (params: RunParams) => Promise<string>;
  cancelRun: (caseId: string) => Promise<void>;
}

export const useRunsStore = create<RunsState>((set, get) => ({
  runs: [],
  selectedRunId: null,
  loading: false,
  error: null,

  fetchRuns: async () => {
    set({ loading: true, error: null });
    try {
      const runs = await api.fetchRuns();
      set({ runs, loading: false });
    } catch (e) {
      set({ error: (e as Error).message, loading: false });
    }
  },

  selectRun: (id) => set({ selectedRunId: id }),

  startRun: async (params: RunParams) => {
    const runId = params.case_id;
    const pending: Run = {
      id: runId,
      params,
      status: 'running',
      started_at: new Date().toISOString(),
      alert_count: 0,
    };
    set((s) => ({
      runs: [pending, ...s.runs.filter((r) => r.id !== runId)],
      selectedRunId: runId,
      error: null,
    }));

    try {
      const completed = await api.startRun(params);
      set((s) => ({
        runs: [completed, ...s.runs.filter((r) => r.id !== runId)],
        selectedRunId: completed.id,
      }));
      return completed.id;
    } catch (e) {
      const failed: Run = {
        ...pending,
        status: 'failed',
        current_stage: undefined,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - new Date(pending.started_at).getTime(),
        error: (e as Error).message,
      };
      set((s) => ({
        runs: [failed, ...s.runs.filter((r) => r.id !== runId)],
        selectedRunId: failed.id,
      }));
      throw e;
    }
  },

  cancelRun: async (caseId: string) => {
    try {
      await api.cancelRun(caseId);
      set((s) => ({
        runs: s.runs.map((run) => {
          if (run.params.case_id !== caseId) return run;
          return {
            ...run,
            status: run.status === 'running' ? 'failed' : run.status,
            current_stage: undefined,
            error: run.error ?? `Run ${caseId} cancelled by user`,
            completed_at: run.completed_at ?? new Date().toISOString(),
          };
        }),
      }));
    } finally {
      await get().fetchRuns();
    }
  },
}));

/* ═══════════════════════════════════════════
   Case Store
   ═══════════════════════════════════════════ */
interface CaseState {
  activeCase: Case | null;
  loading: boolean;
  error: string | null;
  reviewedCases: Record<string, { reviewed_at: string; reviewer?: string }>;
  fetchCase: (caseId: string) => Promise<void>;
  markCaseReviewed: (caseId: string) => void;
  unmarkCaseReviewed: (caseId: string) => void;
  isCaseReviewed: (caseId: string) => boolean;
}

export const useCaseStore = create<CaseState>()(
  persist(
    (set, get) => ({
      activeCase: null,
      loading: false,
      error: null,
      reviewedCases: {},

      fetchCase: async (caseId: string) => {
        set({ loading: true, error: null });
        try {
          const c = await api.fetchCase(caseId);
          if (!c) throw new Error(`Case ${caseId} not found`);
          const alerts = applyAlertPolicies(c.alerts);
          set({
            activeCase: {
              ...c,
              alerts,
              stats: deriveStatsFromAlerts(c.stats, alerts),
            },
            loading: false,
          });
        } catch (e) {
          set({ error: (e as Error).message, loading: false });
        }
      },

      markCaseReviewed: (caseId) =>
        set((s) => ({
          reviewedCases: {
            ...s.reviewedCases,
            [caseId]: { reviewed_at: new Date().toISOString() },
          },
        })),

      unmarkCaseReviewed: (caseId) =>
        set((s) => {
          const { [caseId]: _, ...rest } = s.reviewedCases;
          return { reviewedCases: rest };
        }),

      isCaseReviewed: (caseId) => !!get().reviewedCases[caseId],
    }),
    {
      name: 'wst-case-state',
      partialize: (s) => ({ reviewedCases: s.reviewedCases }),
    },
  ),
);

/* ═══════════════════════════════════════════
   Alerts Store
   ═══════════════════════════════════════════ */
interface AlertsState {
  alerts: Alert[];
  activeCaseId: string | null;
  loading: boolean;
  error: string | null;
  filters: AlertFilters;
  sort: AlertSort;
  selectedAlertId: string | null;
  fetchAlerts: (caseId?: string) => Promise<void>;
  setFilters: (filters: Partial<AlertFilters>) => void;
  setSort: (sort: AlertSort) => void;
  selectAlert: (id: string | null) => void;
  resetFilters: () => void;
}

export const useAlertsStore = create<AlertsState>()(
  persist(
    (set) => ({
      alerts: [],
      activeCaseId: null,
      loading: false,
      error: null,
      filters: DEFAULT_FILTERS,
      sort: DEFAULT_SORT,
      selectedAlertId: null,

      fetchAlerts: async (caseId?: string) => {
        set({ loading: true, error: null });
        try {
          const payload = await api.fetchAlerts(caseId);
          const nextAlerts = applyAlertPolicies(payload.alerts);
          set({ alerts: nextAlerts, activeCaseId: payload.case_id, loading: false });
        } catch (e) {
          set({ error: (e as Error).message, loading: false });
        }
      },

      setFilters: (patch) =>
        set((s) => ({ filters: { ...s.filters, ...patch } })),

      setSort: (sort) => set({ sort }),
      selectAlert: (id) => set({ selectedAlertId: id }),
      resetFilters: () => set({ filters: DEFAULT_FILTERS }),
    }),
    {
      name: 'wst-alerts-state',
      partialize: (s) => ({ filters: s.filters, sort: s.sort }),
    },
  ),
);

/* ═══════════════════════════════════════════
   Toast Store
   ═══════════════════════════════════════════ */

// Reusable AudioContext singleton for toast notification sounds.
// Avoids creating a new AudioContext per toast which can exhaust browser limits.
let sharedAudioCtx: AudioContext | null = null;
function getAudioContext(): AudioContext | null {
  if (typeof window === 'undefined' || !('AudioContext' in window)) return null;
  if (!sharedAudioCtx || sharedAudioCtx.state === 'closed') {
    try {
      sharedAudioCtx = new window.AudioContext();
    } catch {
      return null;
    }
  }
  return sharedAudioCtx;
}

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
  duration?: number;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: Toast['type'], message: string, duration?: number) => void;
  removeToast: (id: string) => void;
}

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  addToast: (type, message, duration?: number) => {
    const notificationSettings = useSettingsStore.getState().notifications;
    if (type === 'success' && !notificationSettings.show_success_toasts) return;
    if (type === 'info' && !notificationSettings.show_info_toasts) return;

    const id = crypto.randomUUID();
    set((s) => ({ toasts: [...s.toasts, { id, type, message }] }));

    if (notificationSettings.sound_enabled) {
      try {
        const ctx = getAudioContext();
        if (ctx) {
          if (ctx.state === 'suspended') void ctx.resume();
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = 'sine';
          osc.frequency.value = type === 'error' ? 240 : 480;
          gain.gain.value = 0.015;
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start();
          osc.stop(ctx.currentTime + 0.08);
        }
      } catch {
        // no-op
      }
    }

    if (notificationSettings.desktop_notifications && typeof Notification !== 'undefined') {
      if (Notification.permission === 'granted') {
        new Notification(`Wazuh Triage (${type})`, { body: message });
      } else if (Notification.permission === 'default') {
        void Notification.requestPermission().then((permission) => {
          if (permission === 'granted') {
            new Notification(`Wazuh Triage (${type})`, { body: message });
          }
        });
      }
    }

    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, duration ?? Math.max(500, notificationSettings.toast_duration_ms));
  },
  removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

/* ═══════════════════════════════════════════
   Alert Annotations Store (notes, FP, escalation)
   ═══════════════════════════════════════════ */
export interface AlertNote {
  id: string;
  text: string;
  created_at: string;
}

export interface AlertAnnotation {
  false_positive: boolean;
  escalated: boolean;
  pinned: boolean;
  notes: AlertNote[];
}

interface AlertAnnotationsState {
  annotations: Record<string, AlertAnnotation>;
  getAnnotation: (alertId: string) => AlertAnnotation;
  toggleFalsePositive: (alertId: string) => void;
  toggleEscalated: (alertId: string) => void;
  togglePinned: (alertId: string) => void;
  addNote: (alertId: string, text: string) => void;
  removeNote: (alertId: string, noteId: string) => void;
  isFalsePositive: (alertId: string) => boolean;
  isEscalated: (alertId: string) => boolean;
  isPinned: (alertId: string) => boolean;
}

const EMPTY_ANNOTATION: AlertAnnotation = { false_positive: false, escalated: false, pinned: false, notes: [] };

export const useAlertAnnotationsStore = create<AlertAnnotationsState>()(
  persist(
    (set, get) => ({
      annotations: {},

      getAnnotation: (alertId) => get().annotations[alertId] ?? EMPTY_ANNOTATION,

      toggleFalsePositive: (alertId) =>
        set((s) => {
          const current = s.annotations[alertId] ?? { ...EMPTY_ANNOTATION };
          return {
            annotations: {
              ...s.annotations,
              [alertId]: { ...current, false_positive: !current.false_positive },
            },
          };
        }),

      toggleEscalated: (alertId) =>
        set((s) => {
          const current = s.annotations[alertId] ?? { ...EMPTY_ANNOTATION };
          return {
            annotations: {
              ...s.annotations,
              [alertId]: { ...current, escalated: !current.escalated },
            },
          };
        }),

      togglePinned: (alertId) =>
        set((s) => {
          const current = s.annotations[alertId] ?? { ...EMPTY_ANNOTATION };
          return {
            annotations: {
              ...s.annotations,
              [alertId]: { ...current, pinned: !current.pinned },
            },
          };
        }),

      addNote: (alertId, text) =>
        set((s) => {
          const current = s.annotations[alertId] ?? { ...EMPTY_ANNOTATION };
          const note: AlertNote = {
            id: crypto.randomUUID(),
            text,
            created_at: new Date().toISOString(),
          };
          return {
            annotations: {
              ...s.annotations,
              [alertId]: { ...current, notes: [...current.notes, note] },
            },
          };
        }),

      removeNote: (alertId, noteId) =>
        set((s) => {
          const current = s.annotations[alertId];
          if (!current) return s;
          return {
            annotations: {
              ...s.annotations,
              [alertId]: {
                ...current,
                notes: current.notes.filter((n) => n.id !== noteId),
              },
            },
          };
        }),

      isFalsePositive: (alertId) => get().annotations[alertId]?.false_positive ?? false,
      isEscalated: (alertId) => get().annotations[alertId]?.escalated ?? false,
      isPinned: (alertId) => get().annotations[alertId]?.pinned ?? false,
    }),
    { name: 'wst-alert-annotations' },
  ),
);
