import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';

// Settings store tests
describe('useSettingsStore', () => {
  // Fresh import per test to reset persisted state
  let useSettingsStore: typeof import('../stores/settings-store').useSettingsStore;

  beforeEach(async () => {
    localStorage.clear();
    // Re-import to get fresh store
    const mod = await import('../stores/settings-store');
    useSettingsStore = mod.useSettingsStore;
    act(() => { useSettingsStore.getState().resetAll(); });
  });

  it('has sensible defaults', () => {
    const s = useSettingsStore.getState();
    expect(s.api.opensearch_url).toBe('https://localhost:9200');
    expect(s.api.verify_tls).toBe(true);
    expect(s.thresholds.high_confidence_min_score).toBe(80);
    expect(s.display.theme).toBe('dark');
    expect(s.presets.length).toBeGreaterThanOrEqual(3);
    expect(s.runAllowlistImages).toEqual([]);
    expect(s.suppressionRules).toEqual([]);
    expect(s.exportConfig.default_alert_format).toBe('json');
  });

  it('updates API config', () => {
    act(() => { useSettingsStore.getState().setApi({ opensearch_url: 'https://my-cluster:9200' }); });
    expect(useSettingsStore.getState().api.opensearch_url).toBe('https://my-cluster:9200');
    // Other fields unchanged
    expect(useSettingsStore.getState().api.verify_tls).toBe(true);
  });

  it('adds and removes presets', () => {
    const initial = useSettingsStore.getState().presets.length;
    act(() => {
      useSettingsStore.getState().addPreset({
        id: 'test-1', name: 'Test', mode: 'live', profile: 'soc',
        time_preset: '2h', queues: ['soc_malware'], include_dev_queue: false,
        min_alert_score: 50, out_dir: './out', dry_run: false,
        alerts_only: false, print_stats: true, verify_tls: true,
      });
    });
    expect(useSettingsStore.getState().presets.length).toBe(initial + 1);

    act(() => { useSettingsStore.getState().removePreset('test-1'); });
    expect(useSettingsStore.getState().presets.length).toBe(initial);
  });

  it('updates thresholds', () => {
    act(() => { useSettingsStore.getState().setThresholds({ auto_escalate_score: 95 }); });
    expect(useSettingsStore.getState().thresholds.auto_escalate_score).toBe(95);
  });

  it('updates display options', () => {
    act(() => { useSettingsStore.getState().setDisplay({ density: 'compact', date_format: 'relative' }); });
    expect(useSettingsStore.getState().display.density).toBe('compact');
    expect(useSettingsStore.getState().display.date_format).toBe('relative');
  });

  it('adds and toggles suppression rules', () => {
    act(() => {
      useSettingsStore.getState().addSuppressionRule({
        id: 'sr-1', name: 'Block Defender', field: 'image',
        pattern: 'MsMpEng.exe', enabled: true, created_at: '2026-01-01T00:00:00Z',
      });
    });
    expect(useSettingsStore.getState().suppressionRules.length).toBe(1);
    expect(useSettingsStore.getState().suppressionRules[0].enabled).toBe(true);

    act(() => { useSettingsStore.getState().updateSuppressionRule('sr-1', { enabled: false }); });
    expect(useSettingsStore.getState().suppressionRules[0].enabled).toBe(false);

    act(() => { useSettingsStore.getState().removeSuppressionRule('sr-1'); });
    expect(useSettingsStore.getState().suppressionRules.length).toBe(0);
  });

  it('adds, edits, and removes run allowlist entries', () => {
    act(() => { useSettingsStore.getState().addRunAllowlistImage('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'); });
    act(() => { useSettingsStore.getState().addRunAllowlistImage('MsMpEng.exe'); });
    expect(useSettingsStore.getState().runAllowlistImages).toEqual(['chrome.exe', 'msmpeng.exe']);

    act(() => { useSettingsStore.getState().updateRunAllowlistImage(0, 'C:\\Windows\\System32\\svchost.exe'); });
    expect(useSettingsStore.getState().runAllowlistImages).toEqual(['svchost.exe', 'msmpeng.exe']);

    act(() => { useSettingsStore.getState().removeRunAllowlistImage(1); });
    expect(useSettingsStore.getState().runAllowlistImages).toEqual(['svchost.exe']);
  });

  it('exports and imports settings', () => {
    act(() => { useSettingsStore.getState().setApi({ timeout_seconds: 99 }); });
    act(() => { useSettingsStore.getState().setRunAllowlistImages(['chrome.exe', '  C:\\Tools\\agent.exe  ']); });
    const json = useSettingsStore.getState().exportSettings();
    const parsed = JSON.parse(json);
    expect(parsed.api.timeout_seconds).toBe(99);
    expect(parsed.runAllowlistImages).toEqual(['chrome.exe', 'agent.exe']);

    // Reset and reimport
    act(() => { useSettingsStore.getState().resetAll(); });
    expect(useSettingsStore.getState().api.timeout_seconds).toBe(30);

    act(() => { useSettingsStore.getState().importSettings(json); });
    expect(useSettingsStore.getState().api.timeout_seconds).toBe(99);
    expect(useSettingsStore.getState().runAllowlistImages).toEqual(['chrome.exe', 'agent.exe']);
  });

  it('handles invalid import gracefully', () => {
    const result = useSettingsStore.getState().importSettings('not json');
    expect(result).toBe(false);
  });

  it('resets all to defaults', () => {
    act(() => {
      useSettingsStore.getState().setApi({ opensearch_url: 'https://changed' });
      useSettingsStore.getState().setThresholds({ auto_escalate_score: 99 });
      useSettingsStore.getState().resetAll();
    });
    expect(useSettingsStore.getState().api.opensearch_url).toBe('https://localhost:9200');
    expect(useSettingsStore.getState().thresholds.auto_escalate_score).toBe(90);
  });
});

// Alert annotations store tests
describe('useAlertAnnotationsStore', () => {
  let useAlertAnnotationsStore: typeof import('../stores').useAlertAnnotationsStore;

  beforeEach(async () => {
    localStorage.clear();
    const mod = await import('../stores');
    useAlertAnnotationsStore = mod.useAlertAnnotationsStore;
    // Clear annotations by resetting the store state directly
    useAlertAnnotationsStore.setState({ annotations: {} });
  });

  it('starts with empty annotations', () => {
    const ann = useAlertAnnotationsStore.getState().getAnnotation('A0001');
    expect(ann.false_positive).toBe(false);
    expect(ann.escalated).toBe(false);
    expect(ann.notes).toEqual([]);
  });

  it('toggles false positive', () => {
    act(() => { useAlertAnnotationsStore.getState().toggleFalsePositive('A0001'); });
    expect(useAlertAnnotationsStore.getState().isFalsePositive('A0001')).toBe(true);

    act(() => { useAlertAnnotationsStore.getState().toggleFalsePositive('A0001'); });
    expect(useAlertAnnotationsStore.getState().isFalsePositive('A0001')).toBe(false);
  });

  it('toggles escalation', () => {
    act(() => { useAlertAnnotationsStore.getState().toggleEscalated('A0001'); });
    expect(useAlertAnnotationsStore.getState().isEscalated('A0001')).toBe(true);

    act(() => { useAlertAnnotationsStore.getState().toggleEscalated('A0001'); });
    expect(useAlertAnnotationsStore.getState().isEscalated('A0001')).toBe(false);
  });

  it('adds and removes notes', () => {
    act(() => { useAlertAnnotationsStore.getState().addNote('A0001', 'Test note 1'); });
    act(() => { useAlertAnnotationsStore.getState().addNote('A0001', 'Test note 2'); });

    const ann = useAlertAnnotationsStore.getState().getAnnotation('A0001');
    expect(ann.notes.length).toBe(2);
    expect(ann.notes[0].text).toBe('Test note 1');
    expect(ann.notes[1].text).toBe('Test note 2');

    const noteId = ann.notes[0].id;
    act(() => { useAlertAnnotationsStore.getState().removeNote('A0001', noteId); });
    expect(useAlertAnnotationsStore.getState().getAnnotation('A0001').notes.length).toBe(1);
  });

  it('tracks annotations independently per alert', () => {
    act(() => {
      useAlertAnnotationsStore.getState().toggleFalsePositive('A0001');
      useAlertAnnotationsStore.getState().toggleEscalated('A0002');
      useAlertAnnotationsStore.getState().addNote('A0003', 'Note for A0003');
    });

    expect(useAlertAnnotationsStore.getState().isFalsePositive('A0001')).toBe(true);
    expect(useAlertAnnotationsStore.getState().isFalsePositive('A0002')).toBe(false);
    expect(useAlertAnnotationsStore.getState().isEscalated('A0002')).toBe(true);
    expect(useAlertAnnotationsStore.getState().isEscalated('A0001')).toBe(false);
    expect(useAlertAnnotationsStore.getState().getAnnotation('A0003').notes.length).toBe(1);
  });
});

// Case reviewed store tests
describe('useCaseStore reviewed tracking', () => {
  let useCaseStore: typeof import('../stores').useCaseStore;

  beforeEach(async () => {
    localStorage.clear();
    const mod = await import('../stores');
    useCaseStore = mod.useCaseStore;
    useCaseStore.setState({ reviewedCases: {} });
  });

  it('marks and checks case reviewed', () => {
    expect(useCaseStore.getState().isCaseReviewed('CASE-001')).toBe(false);

    act(() => { useCaseStore.getState().markCaseReviewed('CASE-001'); });
    expect(useCaseStore.getState().isCaseReviewed('CASE-001')).toBe(true);
    expect(useCaseStore.getState().reviewedCases['CASE-001']).toBeDefined();
    expect(useCaseStore.getState().reviewedCases['CASE-001'].reviewed_at).toBeTruthy();
  });

  it('unmarks case reviewed', () => {
    act(() => { useCaseStore.getState().markCaseReviewed('CASE-001'); });
    act(() => { useCaseStore.getState().unmarkCaseReviewed('CASE-001'); });
    expect(useCaseStore.getState().isCaseReviewed('CASE-001')).toBe(false);
  });
});

describe('useToastStore runtime notification settings', () => {
  let useToastStore: typeof import('../stores').useToastStore;
  let useSettingsStore: typeof import('../stores').useSettingsStore;

  beforeEach(async () => {
    vi.useFakeTimers();
    localStorage.clear();
    const mod = await import('../stores');
    useToastStore = mod.useToastStore;
    useSettingsStore = mod.useSettingsStore;
    act(() => {
      useToastStore.setState({ toasts: [] });
      useSettingsStore.getState().resetAll();
    });
  });

  it('suppresses info toasts when disabled', () => {
    act(() => { useSettingsStore.getState().setNotifications({ show_info_toasts: false }); });
    act(() => { useToastStore.getState().addToast('info', 'hidden'); });
    expect(useToastStore.getState().toasts).toHaveLength(0);
  });

  it('suppresses success toasts when disabled', () => {
    act(() => { useSettingsStore.getState().setNotifications({ show_success_toasts: false }); });
    act(() => { useToastStore.getState().addToast('success', 'hidden'); });
    expect(useToastStore.getState().toasts).toHaveLength(0);
  });

  it('uses configured toast duration', () => {
    act(() => { useSettingsStore.getState().setNotifications({ toast_duration_ms: 1200 }); });
    act(() => { useToastStore.getState().addToast('error', 'visible'); });
    expect(useToastStore.getState().toasts).toHaveLength(1);

    act(() => { vi.advanceTimersByTime(1199); });
    expect(useToastStore.getState().toasts).toHaveLength(1);

    act(() => { vi.advanceTimersByTime(1); });
    expect(useToastStore.getState().toasts).toHaveLength(0);
  });

  afterEach(() => {
    vi.useRealTimers();
  });
});
