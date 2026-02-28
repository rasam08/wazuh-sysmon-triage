import { expect, test, type Route } from '@playwright/test';

const DEFAULT_CASE_ID = 'SMOKE-CASE-001';
const NOW = '2026-02-27T12:00:00.000Z';
let runsShouldFail = false;

function runPayload(caseId: string) {
  return {
    id: caseId,
    params: {
      mode: 'offline',
      profile: 'soc',
      time_preset: '2h',
      queues: ['soc_malware', 'soc_policy'],
      include_dev_queue: false,
      min_alert_score: 70,
      out_dir: '../out',
      case_id: caseId,
      dry_run: false,
      alerts_only: false,
      print_stats: true,
      verify_tls: false,
    },
    status: 'success',
    started_at: NOW,
    completed_at: NOW,
    duration_ms: 1250,
    alert_count: 1,
    stats: {
      total_events: 1,
      by_event_id: { '1': 1 },
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
    metadata: {
      run_id: caseId,
      case_id: caseId,
      started_at: NOW,
      completed_at: NOW,
      duration_ms: 1250,
      schema_version: '1.1.0',
      params: {
        mode: 'offline',
        profile: 'soc',
        time_preset: '2h',
        queues: ['soc_malware', 'soc_policy'],
        include_dev_queue: false,
        min_alert_score: 70,
        out_dir: '../out',
        case_id: caseId,
        dry_run: false,
        alerts_only: false,
        print_stats: true,
        verify_tls: false,
      },
      stages: [
        {
          name: 'detect',
          started_at: NOW,
          completed_at: NOW,
          duration_ms: 200,
          status: 'success',
        },
      ],
    },
  };
}

function alertPayload() {
  return {
    alert_id: 'A001',
    utc_time: NOW,
    score: 96,
    alert_type: 'powershell_obfuscation',
    category: 'malware_execution',
    queue: 'soc_malware',
    confidence: 'high',
    reason: 'PowerShell obfuscation detected',
    routing_why: 'High confidence malware behavior',
    image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    command_line: 'powershell.exe -enc ...',
    parent_image: 'C:\\Windows\\explorer.exe',
    destination_ip: '',
    destination_port: null,
    process_guid: '{PS-ENC}',
    tags: ['signal:obfuscation'],
  };
}

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

test.beforeEach(async ({ page }) => {
  runsShouldFail = false;
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const pathname = url.pathname;

    if (pathname === '/api/runs' && method === 'GET') {
      if (runsShouldFail) {
        await fulfillJson(route, 500, { error: 'Internal server error' });
        return;
      }
      await fulfillJson(route, 200, { runs: [runPayload(DEFAULT_CASE_ID)] });
      return;
    }

    if (pathname === '/api/runs' && method === 'POST') {
      const payload = request.postDataJSON() as { params?: { case_id?: string } } | null;
      const caseId = payload?.params?.case_id || DEFAULT_CASE_ID;
      await fulfillJson(route, 200, { run: runPayload(caseId) });
      return;
    }

    if (pathname === '/api/alerts' && method === 'GET') {
      const caseId = url.searchParams.get('case') ?? DEFAULT_CASE_ID;
      await fulfillJson(route, 200, { case_id: caseId, alerts: [alertPayload()] });
      return;
    }

    if (pathname.startsWith('/api/alerts/') && pathname.endsWith('/bundle') && method === 'GET') {
      await fulfillJson(route, 200, {
        bundle: {
          alert: alertPayload(),
          related_events: [
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
          process_context: [
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
          network_context: [],
        },
      });
      return;
    }

    if (pathname === '/api/health' && method === 'GET') {
      await fulfillJson(route, 200, {
        health: {
          checked_at: NOW,
          profile: 'soc',
          opensearch_host: null,
          opensearch_connectivity: 'not_configured',
          opensearch_http_status: null,
          tls_mode: 'unknown',
          last_successful_fetch_at: null,
        },
      });
      return;
    }

    await fulfillJson(route, 404, { error: `Unhandled mocked route: ${method} ${pathname}` });
  });
});

test('dashboard loads and smoke scenario flow opens alert drawer', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

  await page.getByRole('link', { name: 'Simulate' }).click();
  await expect(page.getByRole('heading', { name: 'Scenario Gym' })).toBeVisible();

  await page.getByText('Encoded PowerShell Download Cradle').click();
  await page.getByRole('button', { name: 'Run Scenario' }).click();
  await expect(page.getByRole('button', { name: 'Open Alerts' })).toBeVisible();

  await page.getByRole('button', { name: 'Open Alerts' }).click();
  await expect(page).toHaveURL(/\/alerts\?case=/);

  await expect(page.getByRole('button', { name: 'A001' })).toBeVisible();
  await page.getByRole('button', { name: 'A001' }).click();
  await expect(page.getByRole('dialog', { name: 'Alert A001' })).toBeVisible();
});

test('dashboard shows error state when runs API fails', async ({ page }) => {
  runsShouldFail = true;

  await page.goto('/dashboard');
  await expect(page.getByText('Internal server error')).toBeVisible();
});
