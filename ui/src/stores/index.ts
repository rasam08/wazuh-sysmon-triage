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
  submitRun: (params: RunParams) => Promise<{ runId: string; executionMode: 'async' | 'sync' }>;
  fetchJobStatus: (jobId: string) => Promise<void>;
  subscribeRunProgress: (jobId: string) => (() => void);
  startRun: (params: RunParams) => Promise<string>;
  cancelRun: (caseId: string) => Promise<void>;
}

const activeJobPollers = new Map<string, ReturnType<typeof setInterval>>();
const activeJobStreams = new Map<string, () => void>();
const JOB_POLL_INTERVAL_MS = 2000;
const JOB_STREAM_FALLBACK_POLL_INTERVAL_MS = 15000;

function stopJobPoller(jobId: string): void {
  const timer = activeJobPollers.get(jobId);
  if (!timer) return;
  clearInterval(timer);
  activeJobPollers.delete(jobId);
}

function stopJobStream(jobId: string): void {
  const unsubscribe = activeJobStreams.get(jobId);
  if (!unsubscribe) return;
  unsubscribe();
  activeJobStreams.delete(jobId);
}

function mapJobStatusToRunStatus(status: api.RunJob['status']): Run['status'] {
  if (status === 'queued') return 'pending';
  if (status === 'cancelled') return 'cancelled';
  return status;
}

function toRunFromJob(job: api.RunJob): Run {
  const startedAt = job.started_at ?? job.accepted_at;
  const progress = job.progress_pct;
  const etaSeconds = estimateEtaSeconds(progress, startedAt);
  return {
    id: job.case_id,
    params: job.params,
    status: mapJobStatusToRunStatus(job.status),
    started_at: startedAt,
    completed_at: job.completed_at,
    duration_ms: job.duration_ms,
    job_id: job.job_id,
    queued_at: job.accepted_at,
    progress_pct: progress,
    eta_seconds: etaSeconds,
    cancel_reason: job.cancel_reason,
    error: job.status === 'failed' || job.status === 'cancelled' ? job.message : undefined,
  };
}

function estimateEtaSeconds(progressPct: number | undefined, startedAt: string | undefined): number | undefined {
  if (!startedAt || typeof progressPct !== 'number') return undefined;
  if (!Number.isFinite(progressPct) || progressPct <= 0 || progressPct >= 100) return undefined;
  const elapsedSeconds = Math.max(0, (Date.now() - new Date(startedAt).getTime()) / 1000);
  if (elapsedSeconds <= 0.25) return undefined;
  const totalSeconds = elapsedSeconds / (progressPct / 100);
  const remainingSeconds = Math.max(0, Math.round(totalSeconds - elapsedSeconds));
  return Number.isFinite(remainingSeconds) ? remainingSeconds : undefined;
}

export const useRunsStore = create<RunsState>((set, get) => {
  const upsertRun = (nextRun: Run): void => {
    set((state) => ({
      runs: [nextRun, ...state.runs.filter((existing) => existing.params.case_id !== nextRun.params.case_id)],
      selectedRunId: nextRun.id,
      error: null,
    }));
  };

  const pollJobOnce = async (jobId: string): Promise<void> => {
    const job = await api.fetchJobStatus(jobId);
    const run = toRunFromJob(job);
    upsertRun(run);
    if (['success', 'failed', 'cancelled'].includes(job.status)) {
      stopJobPoller(jobId);
      stopJobStream(jobId);
      if (job.status === 'success') {
        await get().fetchRuns();
      }
    }
  };

  const ensureJobPolling = (jobId: string, intervalMs = JOB_POLL_INTERVAL_MS): void => {
    stopJobPoller(jobId);
    void pollJobOnce(jobId).catch(() => {
      stopJobPoller(jobId);
    });
    const timer = setInterval(() => {
      void pollJobOnce(jobId).catch(() => {
        stopJobPoller(jobId);
      });
    }, intervalMs);
    activeJobPollers.set(jobId, timer);
  };

  const ensureJobStreaming = (jobId: string): void => {
    stopJobStream(jobId);
    const unsubscribe = get().subscribeRunProgress(jobId);
    activeJobStreams.set(jobId, unsubscribe);
  };

  return {
    runs: [],
    selectedRunId: null,
    loading: false,
    error: null,

    fetchRuns: async () => {
      set({ loading: true, error: null });
      try {
        const fetchedRuns = await api.fetchRuns();
        set((state) => {
          const inFlight = state.runs.filter((run) => run.status === 'pending' || run.status === 'running');
          const merged = [...fetchedRuns];
          for (const run of inFlight) {
            if (!merged.some((existing) => existing.params.case_id === run.params.case_id)) {
              merged.unshift(run);
            }
          }
          return { runs: merged, loading: false };
        });
      } catch (e) {
        set({ error: (e as Error).message, loading: false });
      }
    },

    selectRun: (id) => set({ selectedRunId: id }),

    submitRun: async (params: RunParams) => {
      const caseId = params.case_id;
      const queuedAt = new Date().toISOString();
      upsertRun({
        id: caseId,
        params,
        status: 'pending',
        started_at: queuedAt,
        queued_at: queuedAt,
        progress_pct: 0,
      });

      try {
        const submitted = await api.submitRun(params);
        if (submitted.execution_mode === 'async') {
          upsertRun({
            id: caseId,
            params,
            status: 'pending',
            started_at: submitted.accepted_at,
            queued_at: submitted.accepted_at,
            progress_pct: 0,
            job_id: submitted.job_id,
          });
          if (typeof EventSource === 'undefined') {
            ensureJobPolling(submitted.job_id, JOB_POLL_INTERVAL_MS);
          } else {
            ensureJobStreaming(submitted.job_id);
            ensureJobPolling(submitted.job_id, JOB_STREAM_FALLBACK_POLL_INTERVAL_MS);
          }
          return { runId: caseId, executionMode: 'async' };
        }
        upsertRun(submitted.run);
        return { runId: submitted.run.id, executionMode: 'sync' };
      } catch (e) {
        upsertRun({
          id: caseId,
          params,
          status: 'failed',
          started_at: queuedAt,
          completed_at: new Date().toISOString(),
          duration_ms: Date.now() - new Date(queuedAt).getTime(),
          error: (e as Error).message,
        });
        throw e;
      }
    },

    fetchJobStatus: async (jobId: string) => {
      try {
        const job = await api.fetchJobStatus(jobId);
        upsertRun(toRunFromJob(job));
      } catch (e) {
        set({ error: (e as Error).message });
      }
    },

    subscribeRunProgress: (jobId: string) => {
      return api.subscribeRunProgress(
        jobId,
        (event) => {
          set((state) => {
            const existing = state.runs.find((run) => run.job_id === event.job_id);
            if (!existing) return {};
            const status = mapJobStatusToRunStatus(event.status);
            const isTerminal = event.event === 'terminal';
            const etaSeconds = estimateEtaSeconds(event.progress_pct, existing.started_at);
            const nextRun: Run = {
              ...existing,
              status,
              progress_pct: event.progress_pct,
              eta_seconds: etaSeconds,
              cancel_reason: event.cancel_reason,
              ...(isTerminal ? { completed_at: event.ts } : {}),
              ...(status === 'failed' || status === 'cancelled' ? { error: event.message ?? existing.error } : {}),
            };
            return {
              runs: [nextRun, ...state.runs.filter((run) => run.id !== nextRun.id)],
            };
          });
          if (event.event === 'terminal') {
            stopJobPoller(event.job_id);
            stopJobStream(event.job_id);
            if (event.status === 'success') {
              void get().fetchRuns();
            }
          }
        },
        () => {
          ensureJobPolling(jobId, JOB_POLL_INTERVAL_MS);
        },
      );
    },

    startRun: async (params: RunParams) => {
      const runId = params.case_id;
      const pending: Run = {
        id: runId,
        params,
        status: 'running',
        started_at: new Date().toISOString(),
        alert_count: 0,
      };
      upsertRun(pending);

      try {
        const completed = await api.startRun(params);
        upsertRun(completed);
        return completed.id;
      } catch (e) {
        upsertRun({
          ...pending,
          status: 'failed',
          current_stage: undefined,
          completed_at: new Date().toISOString(),
          duration_ms: Date.now() - new Date(pending.started_at).getTime(),
          error: (e as Error).message,
        });
        throw e;
      }
    },

    cancelRun: async (caseId: string) => {
      try {
        const run = get().runs.find((entry) => entry.params.case_id === caseId);
        if (run?.job_id) {
          await api.cancelJob(run.job_id);
          stopJobStream(run.job_id);
          stopJobPoller(run.job_id);
        } else {
          await api.cancelRun(caseId);
        }
        set((state) => ({
          runs: state.runs.map((entry) => {
            if (entry.params.case_id !== caseId) return entry;
            return {
              ...entry,
              status: entry.status === 'running' || entry.status === 'pending' ? 'cancelled' : entry.status,
              current_stage: undefined,
              cancel_reason: entry.cancel_reason ?? 'user',
              error: entry.error ?? `Run ${caseId} cancelled by user`,
              completed_at: entry.completed_at ?? new Date().toISOString(),
            };
          }),
        }));
      } finally {
        await get().fetchRuns();
      }
    },
  };
});

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

interface Toast {
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
interface AlertNote {
  id: string;
  text: string;
  created_at: string;
}

interface AlertAnnotation {
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
