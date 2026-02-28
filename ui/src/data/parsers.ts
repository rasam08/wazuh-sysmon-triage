import type { Alert, AlertFilters, AlertSort, Confidence } from '@/types';
import type { AlertThresholds, SuppressionRule } from '@/stores/settings-store';

/** Default empty filter state */
export const DEFAULT_FILTERS: AlertFilters = {
  search: '',
  queues: [],
  categories: [],
  confidences: [],
  score_min: 0,
  score_max: 100,
  tags: [],
};

export const DEFAULT_SORT: AlertSort = { field: 'score', direction: 'desc' };

const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

function toRegexFromGlob(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

/** Detect patterns likely to cause catastrophic backtracking (ReDoS). */
function isSafeRegex(pattern: string): boolean {
  // Reject nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
  if (/([+*])\)\1|([+*])\)[?]|\([^)]*[+*][^)]*\)[+*]/.test(pattern)) return false;
  // Reject excessively long patterns
  if (pattern.length > 200) return false;
  return true;
}

function valueMatchesPattern(value: string, pattern: string): boolean {
  const source = value.trim();
  const p = pattern.trim();
  if (!source || !p) return false;

  if (p.includes('*')) {
    return toRegexFromGlob(p).test(source);
  }

  try {
    if (!isSafeRegex(p)) {
      // Reject potentially dangerous regex patterns; fall back to substring match
      return source.toLowerCase().includes(p.toLowerCase());
    }
    return new RegExp(p, 'i').test(source);
  } catch {
    return source.toLowerCase().includes(p.toLowerCase());
  }
}

function alertFieldValue(alert: Alert, field: SuppressionRule['field']): string {
  switch (field) {
    case 'image':
      return alert.image ?? '';
    case 'command_line':
      return alert.command_line ?? '';
    case 'destination_ip':
      return alert.destination_ip ?? '';
    case 'parent_image':
      return alert.parent_image ?? '';
    case 'process_guid':
      return alert.process_guid ?? '';
    case 'tags':
      return (alert.tags ?? []).join(' ');
    default:
      return '';
  }
}

export function scoreToConfidence(score: number, thresholds: Pick<AlertThresholds, 'high_confidence_min_score' | 'medium_confidence_min_score'>): Confidence {
  if (score >= thresholds.high_confidence_min_score) return 'high';
  if (score >= thresholds.medium_confidence_min_score) return 'medium';
  return 'low';
}

export function matchesSuppressionRule(alert: Alert, rule: SuppressionRule): boolean {
  if (!rule.enabled || !rule.pattern.trim()) return false;
  const value = alertFieldValue(alert, rule.field);
  return valueMatchesPattern(value, rule.pattern);
}

/** Filter alerts based on active filters */
export function filterAlerts(alerts: Alert[], filters: AlertFilters): Alert[] {
  return alerts.filter((a) => {
    if (filters.search) {
      const q = filters.search.toLowerCase();
      const searchable = [
        a.alert_id, a.reason, a.image, a.command_line, a.parent_image,
        a.destination_ip, a.routing_why, ...(a.tags ?? []),
      ].join(' ').toLowerCase();
      if (!searchable.includes(q)) return false;
    }
    if (filters.queues.length && !filters.queues.includes(a.queue)) return false;
    if (filters.categories.length && !filters.categories.includes(a.category)) return false;
    if (filters.confidences.length && !filters.confidences.includes(a.confidence)) return false;
    if (a.score < filters.score_min || a.score > filters.score_max) return false;
    if (filters.tags.length && !filters.tags.some((t) => a.tags?.includes(t))) return false;
    return true;
  });
}

/** Sort alerts by field + direction */
export function sortAlerts(alerts: Alert[], sort: AlertSort): Alert[] {
  const sorted = [...alerts];
  sorted.sort((a, b) => {
    let cmp = 0;
    switch (sort.field) {
      case 'score':
        cmp = a.score - b.score;
        break;
      case 'utc_time':
        cmp = new Date(a.utc_time).getTime() - new Date(b.utc_time).getTime();
        break;
      case 'queue':
        cmp = a.queue.localeCompare(b.queue);
        break;
      case 'confidence':
        cmp = CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence];
        break;
      case 'category':
        cmp = a.category.localeCompare(b.category);
        break;
    }
    return sort.direction === 'desc' ? -cmp : cmp;
  });
  return sorted;
}

function parseCsvRows(csv: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < csv.length; i += 1) {
    const ch = csv[i];
    const next = csv[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        cell += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (ch === ',' && !inQuotes) {
      row.push(cell);
      cell = '';
      continue;
    }

    if ((ch === '\n' || ch === '\r') && !inQuotes) {
      if (ch === '\r' && next === '\n') i += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
      continue;
    }

    if (ch === '\r' && next === '\n' && inQuotes) {
      cell += '\n';
      i += 1;
      continue;
    }

    cell += ch;
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }

  return rows;
}

function parseCsvRecords(csv: string): Array<Record<string, string>> {
  const rows = parseCsvRows(csv);
  if (rows.length < 2) return [];

  const headers = rows[0].map((header, idx) => {
    const clean = header.trim();
    return idx === 0 ? clean.replace(/^\uFEFF/, '') : clean;
  });
  if (!headers.some(Boolean)) return [];

  const records: Array<Record<string, string>> = [];
  for (const rawValues of rows.slice(1)) {
    const values = rawValues.map((value) => value.trim());
    if (!values.some((value) => value !== '')) continue;

    const row: Record<string, string> = {};
    headers.forEach((header, idx) => {
      if (!header) return;
      row[header] = values[idx] ?? '';
    });
    records.push(row);
  }
  return records;
}

/** Parse CSV string to alert objects (for reading alerts.csv) */
export function parseAlertsCsv(csv: string): Alert[] {
  const rows = parseCsvRecords(csv);
  if (!rows.length) return [];
  return rows.map((obj, i) => {
    return {
      alert_id: obj.alert_id || `A${String(i).padStart(4, '0')}`,
      utc_time: obj.utc_time || '',
      score: parseInt(obj.score, 10) || 0,
      alert_type: obj.alert_type || '',
      category: (obj.category || 'unknown') as Alert['category'],
      queue: (obj.queue || 'soc_info') as Alert['queue'],
      confidence: (obj.confidence || 'low') as Alert['confidence'],
      reason: obj.reason || '',
      routing_why: obj.routing_why || '',
      image: obj.image || '',
      command_line: obj.command_line || '',
      parent_image: obj.parent_image || '',
      destination_ip: obj.destination_ip || '',
      destination_port: obj.destination_port ? parseInt(obj.destination_port, 10) : null,
      process_guid: obj.process_guid || '',
      tags: obj.tags ? obj.tags.split(';') : [],
      derived_fields: obj.derived_fields ? obj.derived_fields.split(';').filter(Boolean) : [],
    };
  });
}

/** Parse timeline CSV */
export function parseTimelineCsv(csv: string): Array<Record<string, string>> {
  return parseCsvRecords(csv);
}
