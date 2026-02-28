import { expect, test, type Route } from '@playwright/test';

const NOW = '2026-02-27T12:00:00.000Z';
let connectivity: 'reachable' | 'unreachable' = 'reachable';

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

test.beforeEach(async ({ page }) => {
  connectivity = 'reachable';
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const pathname = url.pathname;

    if (pathname === '/api/health' && method === 'GET') {
      await fulfillJson(route, 200, {
        health: {
          checked_at: NOW,
          profile: 'soc',
          cli_available: true,
          opensearch_host: 'https://indexer:9200',
          opensearch_connectivity: connectivity,
          opensearch_http_status: connectivity === 'reachable' ? 200 : 503,
          tls_mode: 'verify',
          last_successful_fetch_at: NOW,
        },
      });
      return;
    }

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

    await fulfillJson(route, 404, { error: `Unhandled mocked route: ${method} ${pathname}` });
  });
});

test('settings health badge reflects reachable then unreachable connectivity', async ({ page }) => {
  await page.goto('/settings');

  await expect(page.getByText('Health Status')).toBeVisible();
  await expect(page.getByText('reachable')).toBeVisible();

  connectivity = 'unreachable';
  await page.getByRole('button', { name: 'Re-check Health' }).click();
  await expect(page.getByText('unreachable')).toBeVisible();
});
