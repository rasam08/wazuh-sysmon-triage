import { expect, test, type Route } from '@playwright/test';

const NOW = '2026-02-27T12:00:00.000Z';

const CASE_FIXTURE = {
  case_id: 'test-case',
  run_id: 'RUN-CASE-001',
  time_range: {
    start: '2026-02-27T11:00:00.000Z',
    end: '2026-02-27T12:00:00.000Z',
  },
  profile: 'soc',
  mode: 'offline',
  schema_version: '1.1.0',
  stats: {
    total_events: 42,
    by_event_id: { '1': 20, '3': 12, '11': 10 },
    alerts_generated: 2,
    alerts_suppressed: 1,
    suppression_hits: { 'allowlist:chrome.exe': 1 },
    dropped_events: 0,
    dropped_by_reason: {},
    queues: { soc_malware: 1, soc_policy: 1 },
    categories: { malware_execution: 1, persistence: 1 },
    confidence_distribution: { high: 1, medium: 1, low: 0 },
    network_connections: 7,
    suspicious_destinations: 2,
  },
  alerts: [
    {
      alert_id: 'A001',
      utc_time: NOW,
      score: 95,
      alert_type: 'powershell_obfuscation',
      category: 'malware_execution',
      queue: 'soc_malware',
      confidence: 'high',
      reason: 'Encoded PowerShell execution',
      routing_why: 'High confidence malware behavior',
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc ...',
      parent_image: 'C:\\Windows\\explorer.exe',
      destination_ip: '',
      destination_port: null,
      process_guid: '{PS-ENC}',
      tags: ['signal:obfuscation'],
    },
    {
      alert_id: 'A002',
      utc_time: NOW,
      score: 68,
      alert_type: 'schtasks_persistence',
      category: 'persistence',
      queue: 'soc_policy',
      confidence: 'medium',
      reason: 'Scheduled task persistence pattern',
      routing_why: 'Persistence signal with medium confidence',
      image: 'C:\\Windows\\System32\\schtasks.exe',
      command_line: 'schtasks.exe /create /tn updater',
      parent_image: 'C:\\Windows\\System32\\cmd.exe',
      destination_ip: '',
      destination_port: null,
      process_guid: '{SCHTASKS-1}',
      tags: ['signal:persistence'],
    },
  ],
  timeline: [
    {
      timestamp: NOW,
      event_id: 1,
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc ...',
      parent_image: 'C:\\Windows\\explorer.exe',
      target_filename: '',
      user: 'HOST\\user',
      rule_id: '92203',
      agent_name: 'agent-test',
      agent_id: '999',
    },
  ],
  process_tree: {
    schema_version: '1.1.0',
    agent: { name: 'agent-test', id: '999' },
    time_range: {
      start: '2026-02-27T11:00:00.000Z',
      end: '2026-02-27T12:00:00.000Z',
    },
    nodes: [
      {
        guid: '{CMD-ROOT}',
        pid: 1000,
        image: 'C:\\Windows\\System32\\cmd.exe',
        cmdline: 'cmd.exe /c start',
        user: 'HOST\\user',
        first_seen: NOW,
        last_seen: NOW,
        synthetic: false,
        tags: [],
      },
      {
        guid: '{PS-ENC}',
        pid: 1337,
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        cmdline: 'powershell.exe -enc ...',
        user: 'HOST\\user',
        first_seen: NOW,
        last_seen: NOW,
        synthetic: false,
        tags: ['attack.t1059'],
      },
    ],
    edges: [
      {
        parent_guid: '{CMD-ROOT}',
        child_guid: '{PS-ENC}',
        reason: 'spawned',
      },
    ],
    artifacts: [
      {
        path: 'C:\\Users\\Public\\payload.ps1',
        created_at: NOW,
        creating_process_guid: '{PS-ENC}',
        creating_image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        confidence: 'HIGH',
        reason: 'Dropped script artifact',
        tags: ['ioc:file'],
      },
    ],
  },
  report_md: '# Incident Report\n\n## Executive Summary\n\nPotential malicious PowerShell activity observed.',
  query: {
    index: 'wazuh-alerts-*',
    start: '2026-02-27T11:00:00.000Z',
    end: '2026-02-27T12:00:00.000Z',
    event_ids: [1, 3, 11],
    size: 1000,
  },
  artifacts: [
    {
      path: 'C:\\Users\\Public\\payload.ps1',
      created_at: NOW,
      creating_process_guid: '{PS-ENC}',
      creating_image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      confidence: 'HIGH',
      reason: 'Dropped script artifact',
      tags: ['ioc:file'],
    },
  ],
};

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

test.beforeEach(async ({ page }) => {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const pathname = url.pathname;

    if (pathname === '/api/runs' && method === 'GET') {
      await fulfillJson(route, 200, { runs: [] });
      return;
    }

    if (pathname === '/api/cases/test-case' && method === 'GET') {
      await fulfillJson(route, 200, { case: CASE_FIXTURE });
      return;
    }

    await fulfillJson(route, 404, { error: `Unhandled mocked route: ${method} ${pathname}` });
  });
});

test('case overview renders KPIs, report, and process tree', async ({ page }) => {
  await page.goto('/cases/test-case');

  await expect(page.getByRole('heading', { name: 'test-case' })).toBeVisible();

  await expect(page.getByText('Total Events', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /^Alerts\s+2$/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /High Confidence/i })).toBeVisible();

  await expect(page.getByRole('heading', { name: 'Report' })).toBeVisible();
  await expect(page.getByTestId('case-report-markdown')).toBeVisible();
  await expect(page.getByText('Executive Summary')).toBeVisible();

  await expect(page.getByRole('heading', { name: 'Process Tree' })).toBeVisible();
  await expect(page.getByLabel('Process tree graph')).toBeVisible();
});
