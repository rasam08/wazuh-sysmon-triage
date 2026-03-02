import { describe, it, expect, vi } from 'vitest';
import { deleteCase, fetchCase, fetchHealth } from '@/data/api';
import type { Case } from '@/types';

describe('API client regression', () => {
  it('fetches arbitrary case IDs without hardcoded filtering', async () => {
    const caseId = 'CASE-ARBITRARY-999';
    const fakeCase: Case = {
      case_id: caseId,
      run_id: caseId,
      time_range: { start: '2026-02-23T08:00:00Z', end: '2026-02-23T09:00:00Z' },
      profile: 'soc',
      mode: 'offline',
      schema_version: '1.1.0',
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
      alerts: [],
      timeline: [],
      process_tree: {
        schema_version: '1.1.0',
        agent: { name: 'agent-test', id: '001' },
        time_range: { start: '2026-02-23T08:00:00Z', end: '2026-02-23T09:00:00Z' },
        nodes: [],
        edges: [],
        artifacts: [],
      },
      report_md: '',
      query: {
        index: 'wazuh-alerts-*',
        start: '2026-02-23T08:00:00Z',
        end: '2026-02-23T09:00:00Z',
        event_ids: [1],
        size: 1000,
      },
      artifacts: [],
    };

    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ case: fakeCase }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await fetchCase(caseId);
    expect(result?.case_id).toBe(caseId);
    expect(fetchMock).toHaveBeenCalledWith(`/api/cases/${encodeURIComponent(caseId)}`, undefined);
  });

  it('fetches health status for a profile', async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({
        health: {
          checked_at: '2026-02-26T00:00:00Z',
          profile: 'soc',
          opensearch_host: 'https://indexer:9920',
          opensearch_connectivity: 'reachable',
          opensearch_http_status: 200,
          tls_mode: 'verify',
          last_successful_fetch_at: '2026-02-25T23:58:00Z',
        },
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await fetchHealth('soc');
    expect(result.opensearch_connectivity).toBe('reachable');
    expect(fetchMock).toHaveBeenCalledWith('/api/health?profile=soc', undefined);
  });

  it('deletes a case by ID', async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ deleted: true, case_id: 'CASE-DELETE-123' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await deleteCase('CASE-DELETE-123');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe('/api/cases/CASE-DELETE-123');
    expect((init as RequestInit | undefined)?.method).toBe('DELETE');
    const headers = new Headers((init as RequestInit | undefined)?.headers);
    expect(headers.get('X-Requested-With')).toBe('XMLHttpRequest');
  });
});
