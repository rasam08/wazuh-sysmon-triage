import React from 'react';
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import CaseOverviewScreen from '@/features/cases/CaseOverviewScreen';
import { useCaseStore, useSettingsStore } from '@/stores';
import type { Case } from '@/types';
import * as exportsUtil from '@/utils/exports';
import * as api from '@/data/api';

vi.mock('@/utils/exports', () => ({
  exportReport: vi.fn(),
  exportAlertsCsv: vi.fn(),
  exportCaseBundle: vi.fn(),
  exportAttackNavigatorLayer: vi.fn(),
  exportReportPdf: vi.fn(async () => undefined),
}));

vi.mock('@/data/api', () => ({
  fetchReport: vi.fn(async () => '# Report'),
  deleteCase: vi.fn(async () => undefined),
}));

const SAMPLE_CASE: Case = {
  case_id: 'CASE-UNIT-001',
  run_id: 'CASE-UNIT-001',
  time_range: { start: '2026-02-27T10:00:00Z', end: '2026-02-27T11:00:00Z' },
  profile: 'soc',
  mode: 'offline',
  schema_version: '1.1.0',
  stats: {
    total_events: 10,
    by_event_id: { '1': 10 },
    alerts_generated: 1,
    alerts_suppressed: 0,
    suppression_hits: {},
    dropped_events: 0,
    dropped_by_reason: {},
    queues: { soc_malware: 1 },
    categories: { malware_execution: 1 },
    confidence_distribution: { high: 1 },
    network_connections: 0,
    suspicious_destinations: 0,
  },
  alerts: [
    {
      alert_id: 'A001',
      utc_time: '2026-02-27T10:30:00Z',
      score: 95,
      alert_type: 'powershell_obfuscation',
      category: 'malware_execution',
      queue: 'soc_malware',
      confidence: 'high',
      reason: 'PowerShell obfuscation',
      routing_why: 'Matched detection rule',
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc ...',
      parent_image: 'C:\\Windows\\explorer.exe',
      destination_ip: '',
      destination_port: null,
      process_guid: '{PS-ENC}',
      tags: ['attack.t1059'],
    },
  ],
  timeline: [],
  process_tree: {
    schema_version: '1.1.0',
    agent: { name: 'agent-test', id: '001' },
    time_range: { start: '2026-02-27T10:00:00Z', end: '2026-02-27T11:00:00Z' },
    nodes: [
      {
        guid: '{PS-ENC}',
        pid: 1337,
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        cmdline: 'powershell.exe -enc ...',
        user: 'HOST\\user',
        first_seen: '2026-02-27T10:30:00Z',
        last_seen: '2026-02-27T10:31:00Z',
        synthetic: false,
        tags: ['attack.t1059'],
      },
    ],
    edges: [],
    artifacts: [],
  },
  report_md: '# Report',
  query: {
    index: 'wazuh-alerts-*',
    start: '2026-02-27T10:00:00Z',
    end: '2026-02-27T11:00:00Z',
    event_ids: [1],
    size: 1000,
  },
  artifacts: [],
};

function renderCaseOverview() {
  return render(
    <MemoryRouter initialEntries={['/cases/CASE-UNIT-001']}>
      <Routes>
        <Route path="/cases/:caseId" element={<CaseOverviewScreen />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('CaseOverview exports', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    useSettingsStore.getState().resetAll();
    useCaseStore.setState({
      activeCase: SAMPLE_CASE,
      loading: false,
      error: null,
      fetchCase: vi.fn(async () => undefined),
      reviewedCases: {},
      markCaseReviewed: vi.fn(),
      unmarkCaseReviewed: vi.fn(),
      isCaseReviewed: vi.fn(() => false),
    });
  });

  it('renders process tree section and exports ATT&CK layer', () => {
    renderCaseOverview();
    expect(screen.getByText('Process Tree')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Export ATT&CK Layer' }));
    expect(exportsUtil.exportAttackNavigatorLayer).toHaveBeenCalledWith(expect.objectContaining({
      case_id: 'CASE-UNIT-001',
    }));
  });

  it('exports PDF report from case overview button', async () => {
    renderCaseOverview();
    fireEvent.click(screen.getByRole('button', { name: 'Export PDF' }));

    await waitFor(() => {
      expect(api.fetchReport).toHaveBeenCalledWith('CASE-UNIT-001');
      expect(exportsUtil.exportReportPdf).toHaveBeenCalledWith(
        expect.objectContaining({ case_id: 'CASE-UNIT-001' }),
        '# Report',
      );
    });
  });
});
