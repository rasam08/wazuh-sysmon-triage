import { describe, it, expect, beforeEach, vi } from 'vitest';
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AlertWorkbenchScreen from '@/features/alerts/AlertWorkbenchScreen';
import { useAlertAnnotationsStore, useAlertsStore, useSettingsStore } from '@/stores';
import { DEFAULT_FILTERS, DEFAULT_SORT } from '@/data/parsers';
import type { Alert } from '@/types';
import * as api from '@/data/api';

vi.mock('@/data/api', () => ({
  fetchRuns: vi.fn(async () => []),
  fetchRun: vi.fn(async () => undefined),
  startRun: vi.fn(),
  fetchCase: vi.fn(async () => undefined),
  fetchAlerts: vi.fn(async () => ({ alerts: [], case_id: null })),
  fetchAlertBundle: vi.fn(async () => undefined),
  fetchReport: vi.fn(async () => ''),
}));

function makeAlert(id: string, confidence: Alert['confidence']): Alert {
  return {
    alert_id: id,
    utc_time: '2026-02-23T08:00:00Z',
    score: confidence === 'high' ? 90 : confidence === 'medium' ? 60 : 30,
    alert_type: 'sigma_composite',
    category: 'malware_execution',
    queue: 'soc_malware',
    confidence,
    reason: `reason-${id}`,
    routing_why: `routing-${id}`,
    image: 'C:\\Windows\\System32\\powershell.exe',
    command_line: 'powershell.exe -enc abc',
    parent_image: 'C:\\Windows\\explorer.exe',
    destination_ip: '',
    destination_port: null,
    process_guid: `{${id}}`,
    tags: ['attack.t1059'],
  };
}

function renderAlerts(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path="/alerts" element={<AlertWorkbenchScreen />} />
        <Route path="/alerts/:alertId" element={<AlertWorkbenchScreen />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('Alert workbench regressions', () => {
  beforeEach(() => {
    localStorage.clear();
    useSettingsStore.getState().resetAll();
    useAlertsStore.setState({
      alerts: [],
      activeCaseId: null,
      loading: false,
      error: null,
      filters: DEFAULT_FILTERS,
      sort: DEFAULT_SORT,
      selectedAlertId: null,
    });
    useAlertAnnotationsStore.setState({ annotations: {} });
    vi.clearAllMocks();
  });

  it('hydrates URL filters and requests case-scoped alerts', async () => {
    vi.mocked(api.fetchAlerts).mockResolvedValue({
      alerts: [makeAlert('A0001', 'high'), makeAlert('A0002', 'low')],
      case_id: 'CASE-URL-01',
    });

    renderAlerts('/alerts?case=CASE-URL-01&confidence=high');

    await waitFor(() => {
      expect(api.fetchAlerts).toHaveBeenCalledWith('CASE-URL-01');
    });
    await waitFor(() => {
      expect(screen.getByText('1 of 2 alerts')).toBeInTheDocument();
    });
    expect(screen.getByText('A0001')).toBeInTheDocument();
    expect(screen.queryByText('A0002')).not.toBeInTheDocument();
  });

  it('uses display page size setting for alert table pagination', async () => {
    useSettingsStore.getState().setDisplay({ alerts_page_size: 10 });
    vi.mocked(api.fetchAlerts).mockResolvedValue({
      alerts: Array.from({ length: 12 }, (_, i) => makeAlert(`A${String(i + 1).padStart(4, '0')}`, 'medium')),
      case_id: 'CASE-PAGE-01',
    });

    const { container } = renderAlerts('/alerts?case=CASE-PAGE-01');

    await waitFor(() => {
      expect(container.querySelectorAll('tbody tr').length).toBe(10);
    });
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
  });

  it('supports keyboard shortcuts for triage and alert navigation', async () => {
    vi.mocked(api.fetchAlerts).mockResolvedValue({
      alerts: [makeAlert('A0001', 'high'), makeAlert('A0002', 'medium')],
      case_id: 'CASE-KB-01',
    });

    renderAlerts('/alerts?case=CASE-KB-01');

    await waitFor(() => {
      expect(screen.getByText('A0001')).toBeInTheDocument();
      expect(screen.getByText('A0002')).toBeInTheDocument();
    });

    fireEvent.keyDown(window, { key: 'j' });
    await waitFor(() => {
      expect(screen.getByRole('dialog', { name: 'Alert A0001' })).toBeInTheDocument();
    });

    fireEvent.keyDown(window, { key: 'e' });
    expect(useAlertAnnotationsStore.getState().isEscalated('A0001')).toBe(true);

    fireEvent.keyDown(window, { key: 'f' });
    expect(useAlertAnnotationsStore.getState().isFalsePositive('A0001')).toBe(true);

    fireEvent.keyDown(window, { key: 'j' });
    await waitFor(() => {
      expect(screen.getByRole('dialog', { name: 'Alert A0002' })).toBeInTheDocument();
    });

    fireEvent.keyDown(window, { key: 'k' });
    await waitFor(() => {
      expect(screen.getByRole('dialog', { name: 'Alert A0001' })).toBeInTheDocument();
    });
  });
});
