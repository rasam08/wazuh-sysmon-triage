import '@testing-library/jest-dom';
import { afterEach, vi } from 'vitest';

const defaultFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string'
    ? input
    : input instanceof URL
      ? input.pathname + input.search
      : input.url;
  const method = (init?.method ?? 'GET').toUpperCase();

  if (url.startsWith('/api/runs') && method === 'GET') {
    return new Response(JSON.stringify({ runs: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  if (url.startsWith('/api/runs/preview') && method === 'POST') {
    let params: Record<string, unknown> = {};
    if (typeof init?.body === 'string') {
      try {
        const parsed = JSON.parse(init.body);
        params = (parsed.params ?? {}) as Record<string, unknown>;
      } catch {
        params = {};
      }
    }
    return new Response(
      JSON.stringify({
        preview: {
          params: {
            mode: String(params.mode ?? 'offline'),
            profile: String(params.profile ?? 'soc'),
            time_preset: String(params.time_preset ?? '2h'),
            queues: Array.isArray(params.queues) ? params.queues : ['soc_malware'],
            include_dev_queue: Boolean(params.include_dev_queue),
            min_alert_score: Number(params.min_alert_score ?? 70),
            out_dir: String(params.out_dir ?? './out'),
            case_id: String(params.case_id ?? 'test-case'),
            dry_run: Boolean(params.dry_run),
            alerts_only: Boolean(params.alerts_only),
            print_stats: params.print_stats === undefined ? true : Boolean(params.print_stats),
            verify_tls: params.verify_tls === undefined ? true : Boolean(params.verify_tls),
            ...(params.start ? { start: String(params.start) } : {}),
            ...(params.end ? { end: String(params.end) } : {}),
            ...(params.agent_name ? { agent_name: String(params.agent_name) } : {}),
            ...(params.agent_id ? { agent_id: String(params.agent_id) } : {}),
            ...(params.input_file ? { input_file: String(params.input_file) } : {}),
          },
          cli_args: ['-m', 'wazuh_sysmon_triage', String(params.mode ?? 'offline')],
          command: 'python -m wazuh_sysmon_triage offline',
          warnings: [],
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  }

  if (url === '/api/runs' && method === 'POST') {
    let params: Record<string, unknown> = {};
    if (typeof init?.body === 'string') {
      try {
        const parsed = JSON.parse(init.body);
        params = (parsed.params ?? {}) as Record<string, unknown>;
      } catch {
        params = {};
      }
    }
    const caseId = String(params.case_id ?? 'test-case');
    const now = new Date().toISOString();
    return new Response(
      JSON.stringify({
        run: {
          id: caseId,
          params: {
            mode: 'offline',
            profile: 'soc',
            time_preset: '2h',
            queues: ['soc_malware'],
            include_dev_queue: false,
            min_alert_score: 70,
            out_dir: './out',
            case_id: caseId,
            dry_run: false,
            alerts_only: false,
            print_stats: true,
            verify_tls: true,
          },
          status: 'success',
          started_at: now,
          completed_at: now,
          duration_ms: 100,
          alert_count: 0,
          stats: {
            total_events: 0,
            by_event_id: {},
            alerts_generated: 0,
            alerts_suppressed: 0,
            suppression_hits: {},
            dropped_events: 0,
            dropped_by_reason: {},
            queues: {},
            categories: {},
            confidence_distribution: {},
            network_connections: 0,
            suspicious_destinations: 0,
          },
          metadata: {
            run_id: caseId,
            case_id: caseId,
            started_at: now,
            completed_at: now,
            duration_ms: 100,
            schema_version: '1.1.0',
            params: {
              mode: 'offline',
              profile: 'soc',
              time_preset: '2h',
              queues: ['soc_malware'],
              include_dev_queue: false,
              min_alert_score: 70,
              out_dir: './out',
              case_id: caseId,
              dry_run: false,
              alerts_only: false,
              print_stats: true,
              verify_tls: true,
            },
            stages: [],
          },
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  }

  if (url.startsWith('/api/alerts/') && url.includes('/bundle')) {
    return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }

  if (url.startsWith('/api/alerts')) {
    return new Response(JSON.stringify({ alerts: [], case_id: null }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  if (url.startsWith('/api/cases/')) {
    return new Response(JSON.stringify({ error: 'Case not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }

  if (url.startsWith('/api/report')) {
    return new Response(JSON.stringify({ report: '' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }

  return new Response(JSON.stringify({ error: `Unhandled test API route: ${url}` }), { status: 404, headers: { 'Content-Type': 'application/json' } });
});

vi.stubGlobal('fetch', defaultFetch);

afterEach(() => {
  defaultFetch.mockClear();
});
