import { expect, test, type Route } from '@playwright/test';

const PREVIEW_CLI_COMMAND =
  'python -m wazuh_sysmon_triage live --profile soc --last 2h --agent-name win-workstation-01 --agent-id 001 --case-id CASE-E2E-NEWRUN-001';

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

    if (pathname === '/api/runs/preview' && method === 'POST') {
      const payload = request.postDataJSON() as { params?: Record<string, unknown> } | null;
      await fulfillJson(route, 200, {
        preview: {
          params: payload?.params ?? {},
          cli_args: [
            'python',
            '-m',
            'wazuh_sysmon_triage',
            'live',
            '--profile',
            'soc',
            '--last',
            '2h',
            '--agent-name',
            'win-workstation-01',
            '--agent-id',
            '001',
            '--case-id',
            'CASE-E2E-NEWRUN-001',
          ],
          command: PREVIEW_CLI_COMMAND,
          cli_command: PREVIEW_CLI_COMMAND,
          warnings: [],
        },
      });
      return;
    }

    await fulfillJson(route, 404, { error: `Unhandled mocked route: ${method} ${pathname}` });
  });
});

test('new run preview shows CLI command', async ({ page }) => {
  await page.goto('/new-run');

  await expect(page.getByRole('heading', { name: 'New Triage Run' })).toBeVisible();
  await page.getByPlaceholder('win-workstation-01').fill('win-workstation-01');
  await page.getByPlaceholder('001').fill('001');
  await page.getByLabel('Case ID').fill('CASE-E2E-NEWRUN-001');

  await page.getByRole('button', { name: 'Preview Query' }).click();

  await expect(page.getByRole('heading', { name: 'Query Preview' })).toBeVisible();
  await expect(page.getByText(PREVIEW_CLI_COMMAND)).toBeVisible();
});
