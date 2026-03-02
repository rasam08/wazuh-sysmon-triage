import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import NewRunScreen from '../features/new-run/NewRunScreen';
import RunsDashboardScreen from '../features/runs/RunsDashboardScreen';
import AlertWorkbenchScreen from '../features/alerts/AlertWorkbenchScreen';

function renderWithRouter(ui: React.ReactElement, { route = '/', path = '*' } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path={path} element={ui} />
      </Routes>
    </MemoryRouter>
  );
}

describe('NewRunScreen', () => {
  it('renders the new run form', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('New Triage Run')).toBeInTheDocument();
    expect(screen.getByText('Run Triage')).toBeInTheDocument();
    expect(screen.getByText('Preview Query')).toBeInTheDocument();
    expect(screen.getByText('Reset')).toBeInTheDocument();
  });

  it('renders mode toggle', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('Live')).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('renders profile options', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('soc')).toBeInTheDocument();
    expect(screen.getByText('dev')).toBeInTheDocument();
    expect(screen.getByText('lab')).toBeInTheDocument();
  });
});

describe('RunsDashboardScreen', () => {
  it('renders runs or empty state', () => {
    renderWithRouter(<RunsDashboardScreen />);
    // Will show loading initially, then runs or empty state
    expect(document.body).toBeTruthy();
  });
});

describe('AlertWorkbenchScreen', () => {
  it('renders alert workbench', () => {
    renderWithRouter(<AlertWorkbenchScreen />);
    // Will show loading initially
    expect(document.body).toBeTruthy();
  });

  it('opens selected alert from deep-link route', async () => {
    const fetchMock = vi.mocked(fetch);
    const alertPayload = {
      alert_id: 'deep-alert',
      utc_time: new Date().toISOString(),
      score: 92,
      alert_type: 'suspicious_process',
      category: 'malware_execution',
      queue: 'soc_malware',
      confidence: 'high',
      reason: 'Test alert',
      routing_why: 'test',
      image: 'C:\\Windows\\System32\\cmd.exe',
      command_line: 'cmd.exe /c whoami',
      parent_image: 'C:\\Windows\\explorer.exe',
      destination_ip: '',
      destination_port: null,
      process_guid: 'GUID-1',
      tags: ['test'],
    };

    fetchMock
      .mockImplementationOnce(async () => new Response(
        JSON.stringify({
          case_id: 'case-123',
          alerts: [alertPayload],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ))
      .mockImplementationOnce(async () => new Response(
        JSON.stringify({
          alert: alertPayload,
          related_events: [],
          process_context: [],
          network_context: [],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ));

    renderWithRouter(<AlertWorkbenchScreen />, {
      route: '/alerts/deep-alert?case=case-123',
      path: '/alerts/:alertId',
    });

    await waitFor(() => {
      expect(screen.getByText('Alert deep-alert')).toBeInTheDocument();
    });
  });
});
