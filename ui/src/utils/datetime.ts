import type { DateFormat } from '@/stores/settings-store';
import { useSettingsStore } from '@/stores';

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function toDate(input: string): Date | null {
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function relativeFromNow(input: string): string {
  const date = toDate(input);
  if (!date) return '-';

  const diffMs = date.getTime() - Date.now();
  const abs = Math.abs(diffMs);
  const minute = 60_000;
  const hour = 3_600_000;
  const day = 86_400_000;

  if (abs < minute) return 'just now';
  if (abs < hour) return rtf.format(Math.round(diffMs / minute), 'minute');
  if (abs < day) return rtf.format(Math.round(diffMs / hour), 'hour');
  return rtf.format(Math.round(diffMs / day), 'day');
}

/**
 * Format a datetime string. Accepts an optional `mode` parameter so callers
 * that live inside React components can pass the reactive `date_format` value
 * from `useSettingsStore`. When omitted the current store snapshot is used
 * (adequate for non-reactive / one-shot contexts).
 */
export function formatDateTime(input: string, mode?: DateFormat): string {
  const fmt = mode ?? useSettingsStore.getState().display.date_format;
  const date = toDate(input);
  if (!date) return '-';

  if (fmt === 'relative') return relativeFromNow(input);
  if (fmt === 'locale') return date.toLocaleString();
  return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
}

export function formatTime(input: string, mode?: DateFormat): string {
  const fmt = mode ?? useSettingsStore.getState().display.date_format;
  const date = toDate(input);
  if (!date) return '-';

  if (fmt === 'relative') return relativeFromNow(input);
  if (fmt === 'locale') return date.toLocaleTimeString();
  return date.toISOString().slice(11, 19);
}

export function formatDateRange(start: string, end: string, mode?: DateFormat): string {
  const s = formatDateTime(start, mode);
  const e = formatDateTime(end, mode);
  return `${s} -> ${e}`;
}
