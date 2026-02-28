import { expect, test, type Route } from '@playwright/test';

const NOW = '2026-02-27T12:00:00.000Z';

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

    if (pathname === '/api/cases' && method === 'GET') {
      await fulfillJson(route, 200, { cases: [] });
      return;
    }

    if (pathname === '/api/alerts' && method === 'GET') {
      await fulfillJson(route, 200, { alerts: [] });
      return;
    }

    if (pathname === '/api/health' && method === 'GET') {
      await fulfillJson(route, 200, {
        health: {
          checked_at: NOW,
          profile: 'soc',
          opensearch_host: 'https://indexer:9200',
          opensearch_connectivity: 'reachable',
          opensearch_http_status: 200,
          tls_mode: 'verify',
          last_successful_fetch_at: NOW,
        },
      });
      return;
    }

    await fulfillJson(route, 404, { error: `Unhandled mocked route: ${method} ${pathname}` });
  });
});

test('dashboard shows empty state when there are no runs', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page.getByText('No completed runs yet')).toBeVisible();
});

test('alerts shows empty state when there are no alerts', async ({ page }) => {
  await page.goto('/alerts');
  await expect(page.getByText('No alerts match filters')).toBeVisible();
});

test('cases shows empty state when there are no cases', async ({ page }) => {
  await page.goto('/cases');
  await expect(page.getByText('No cases yet')).toBeVisible();
});

test('runs shows empty state when there are no runs', async ({ page }) => {
  await page.goto('/runs');
  await expect(page.getByText('No runs yet')).toBeVisible();
});
