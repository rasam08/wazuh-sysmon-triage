import React, { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { ToastContainer } from '@/components';
import { GlobalProgressBar } from '@/components/GlobalProgressBar';
import { CommandPalette } from '@/components/CommandPalette';
import { useRunsStore, useSettingsStore, useAlertsStore } from '@/stores';
import { fetchHealth } from '@/data/api';
import type { HealthStatus } from '@/types';

// ─── Icons ──────────────────────────────────────────────────────────────────
function IcoDashboard() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <rect x="1" y="1" width="6" height="6" rx="1.2" />
      <rect x="9" y="1" width="6" height="6" rx="1.2" />
      <rect x="1" y="9" width="6" height="6" rx="1.2" />
      <rect x="9" y="9" width="6" height="6" rx="1.2" />
    </svg>
  );
}
function IcoNewRun() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="8" cy="8" r="6.2" /><path d="M8 5v6M5 8h6" strokeLinecap="round" />
    </svg>
  );
}
function IcoRuns() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M2 4h12M2 8h9M2 12h6" strokeLinecap="round" />
    </svg>
  );
}
function IcoCases() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <rect x="2" y="4.5" width="12" height="8.5" rx="1.5" />
      <path d="M5 4.5V3.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1" strokeLinecap="round" />
    </svg>
  );
}
function IcoAlerts() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M8 2 13.5 13H2.5Z" strokeLinejoin="round" />
      <path d="M8 7v2.5M8 11.5v.5" strokeLinecap="round" />
    </svg>
  );
}
function IcoSimulate() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M5 3.5 12 8 5 12.5Z" strokeLinejoin="round" />
    </svg>
  );
}
function IcoSettings() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="8" cy="8" r="2.2" />
      <path d="M8 1.5v1.2M8 13.3v1.2M1.5 8h1.2M13.3 8h1.2M3.6 3.6l.85.85M11.55 11.55l.85.85M3.6 12.4l.85-.85M11.55 4.45l.85-.85" strokeLinecap="round" />
    </svg>
  );
}
function IcoSearch() {
  return (
    <svg width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="7" cy="7" r="4.5" /><path d="M11 11 14 14" strokeLinecap="round" />
    </svg>
  );
}
function IcoChevronLeft() {
  return (
    <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M10 4 6 8l4 4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ─── Nav config ──────────────────────────────────────────────────────────────
const NAV_MAIN = [
  { to: '/dashboard', label: 'Dashboard', Icon: IcoDashboard },
  { to: '/new-run',   label: 'New Run',   Icon: IcoNewRun },
  { to: '/runs',      label: 'Runs',      Icon: IcoRuns },
  { to: '/cases',     label: 'Cases',     Icon: IcoCases },
  { to: '/alerts',    label: 'Alerts',    Icon: IcoAlerts },
] as const;

const NAV_BOTTOM = [
  { to: '/simulate', label: 'Simulate', Icon: IcoSimulate },
  { to: '/settings', label: 'Settings', Icon: IcoSettings },
] as const;

// ─── SideNavItem ─────────────────────────────────────────────────────────────
function SideNavItem({
  to,
  label,
  Icon,
  collapsed,
  healthDot,
  badge,
}: {
  to: string;
  label: string;
  Icon: React.FC;
  collapsed: boolean;
  healthDot?: 'ok' | 'error' | 'unknown';
  badge?: number;
}) {
  return (
    <NavLink
      to={to}
      title={collapsed ? label : undefined}
      aria-label={label}
      className={({ isActive }) =>
        `relative flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm font-medium transition-colors
         ${isActive
           ? 'bg-blue-600/25 text-blue-300'
           : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'}`
      }
    >
      <span className="flex-shrink-0 w-4 h-4 flex items-center justify-center">
        <Icon />
      </span>
      {!collapsed && <span className="truncate">{label}</span>}
      {/* Notification badge */}
      {typeof badge === 'number' && badge > 0 && (
        <span
          className={`absolute flex items-center justify-center text-[9px] font-bold text-white bg-red-500 rounded-full min-w-[16px] h-[16px] px-1 leading-none
            ${collapsed ? 'top-0 right-0' : 'top-1 right-1.5'}
            badge-pulse`}
          aria-label={`${badge} notification${badge !== 1 ? 's' : ''}`}
        >
          {badge > 99 ? '99+' : badge}
        </span>
      )}
      {healthDot && (
        <span
          className={`absolute top-1 left-6 w-2 h-2 rounded-full border-2 border-gray-900
            ${healthDot === 'ok'    ? 'bg-emerald-400'
            : healthDot === 'error' ? 'bg-red-400 animate-pulse'
            : 'bg-gray-600'}`}
          aria-label={`OpenSearch ${healthDot === 'ok' ? 'connected' : healthDot === 'error' ? 'unreachable' : 'status unknown'}`}
        />
      )}
    </NavLink>
  );
}

// ─── AppLayout ───────────────────────────────────────────────────────────────
export function AppLayout() {
  const { runs, fetchRuns } = useRunsStore();
  const display = useSettingsStore((s) => s.display);
  const alertsLoading = useAlertsStore((s) => s.loading);
  const runsLoading = useRunsStore((s) => s.loading);
  const [systemTheme, setSystemTheme] = useState<'dark' | 'light'>('dark');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem('sidebar-collapsed') === '1'; } catch { return false; }
  });
  const hasFetched = useRef(false);

  // Global loading state from stores
  const isAnyLoading = alertsLoading || runsLoading;

  useEffect(() => {
    try { localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0'); } catch {}
  }, [collapsed]);

  useEffect(() => {
    if (!hasFetched.current) {
      hasFetched.current = true;
      void fetchRuns();
    }
  }, [fetchRuns]);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const media = window.matchMedia('(prefers-color-scheme: light)');
    const sync = () => setSystemTheme(media.matches ? 'light' : 'dark');
    sync();
    media.addEventListener('change', sync);
    return () => media.removeEventListener('change', sync);
  }, []);

  // Poll health once per minute for sidebar indicator
  useEffect(() => {
    let active = true;
    const profile = (runs[0]?.params.profile ?? 'soc') as 'soc' | 'dev' | 'lab';
    const check = () => {
      void fetchHealth(profile)
        .then((payload) => { if (active) setHealth(payload); })
        .catch(() => {});
    };
    check();
    const interval = setInterval(check, 60_000);
    return () => { active = false; clearInterval(interval); };
  }, [runs]);

  const activeTheme = display.theme === 'system' ? systemTheme : display.theme;
  const location = useLocation();

  useEffect(() => {
    const ROUTE_TITLES: Record<string, string> = {
      '/dashboard': 'Dashboard',
      '/new-run': 'New Run',
      '/runs': 'Runs',
      '/cases': 'Cases',
      '/alerts': 'Alert Workbench',
      '/simulate': 'Scenario Gym',
      '/settings': 'Settings',
    };
    const base = 'Wazuh Sysmon Triage';
    const match = Object.entries(ROUTE_TITLES).find(([prefix]) =>
      location.pathname === prefix || location.pathname.startsWith(prefix + '/'),
    );
    document.title = match ? `${match[1]} - ${base}` : base;
  }, [location.pathname]);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = activeTheme;
    root.dataset.density = display.density;
    root.dataset.motion = display.animations_enabled ? 'enabled' : 'disabled';
    root.dataset.monospaceCommands = display.monospace_commands ? 'enabled' : 'disabled';
  }, [activeTheme, display.density, display.animations_enabled, display.monospace_commands]);

  const healthDot: 'ok' | 'error' | 'unknown' = health
    ? (health.opensearch_connectivity === 'reachable'   ? 'ok'
      : health.opensearch_connectivity === 'unreachable' ? 'error'
      : 'unknown')
    : 'unknown';

  // Compute badge counts for nav items
  const runningCount = runs.filter((r) => r.status === 'running').length;
  const navBadges: Record<string, number> = {
    '/runs': runningCount,
  };

  return (
    <div className="min-h-screen flex bg-gray-950 text-gray-100">
      {/* Global loading indicator */}
      <GlobalProgressBar active={isAnyLoading} />

      {/* Skip link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:px-4 focus:py-2 focus:bg-blue-600 focus:text-white focus:rounded-md focus:text-sm focus:font-medium"
      >
        Skip to main content
      </a>

      {/* ── Sidebar ── */}
      <aside
        className={`flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col
          transition-[width] duration-200 ease-in-out overflow-hidden sticky top-0 h-screen
          ${collapsed ? 'w-[52px]' : 'w-48'}`}
        aria-label="Sidebar navigation"
      >
        {/* Logo + collapse toggle */}
        <div
          className={`h-14 flex items-center border-b border-gray-800 flex-shrink-0
            ${collapsed ? 'justify-center px-2' : 'px-3 gap-2'}`}
        >
          {!collapsed && (
            <NavLink to="/dashboard" className="flex items-center gap-2 flex-1 min-w-0">
              <img src="/logo.png" alt="" className="w-7 h-7 object-contain flex-shrink-0 rounded-md" style={{ background: 'radial-gradient(circle, #0d1b2e 60%, transparent)' }} />
              <span className="font-semibold text-xs text-gray-200 truncate">Wazuh Triage</span>
            </NavLink>
          )}
          {collapsed && (
            <NavLink to="/dashboard" className="flex items-center justify-center mb-1">
              <img src="/logo.png" alt="Wazuh Triage" className="w-7 h-7 object-contain rounded-md" style={{ background: 'radial-gradient(circle, #0d1b2e 60%, transparent)' }} />
            </NavLink>
          )}
          <button
            onClick={() => setCollapsed((c) => !c)}
            className={`flex-shrink-0 p-1.5 rounded-md hover:bg-gray-800 text-gray-500 hover:text-gray-300
              transition-all duration-200 ${collapsed ? '' : 'rotate-180'}`}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <IcoChevronLeft />
          </button>
        </div>

        {/* Command palette trigger */}
        <div className={`px-2 py-2 border-b border-gray-800/50 ${collapsed ? 'flex justify-center' : ''}`}>
          <button
            onClick={() =>
              window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))
            }
            title="Search (Ctrl+K)"
            aria-label="Open command palette (Ctrl+K)"
            className={`flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300
              bg-gray-800/40 hover:bg-gray-800 border border-gray-700/40 rounded-md transition-colors
              ${collapsed ? 'p-2' : 'w-full px-2.5 py-1.5'}`}
          >
            <IcoSearch />
            {!collapsed && (
              <>
                <span className="flex-1 text-left">Search…</span>
                <kbd className="text-[10px] text-gray-600 font-mono bg-gray-900 px-1 rounded">^K</kbd>
              </>
            )}
          </button>
        </div>

        {/* Main nav */}
        <nav className="flex-1 overflow-y-auto py-2 px-1.5 space-y-0.5" aria-label="Main navigation">
          {NAV_MAIN.map((item) => (
            <SideNavItem key={item.to} {...item} collapsed={collapsed} badge={navBadges[item.to]} />
          ))}
        </nav>

        {/* Bottom nav */}
        <div className="py-2 px-1.5 space-y-0.5 border-t border-gray-800 flex-shrink-0">
          <SideNavItem {...NAV_BOTTOM[0]} collapsed={collapsed} />
          <SideNavItem {...NAV_BOTTOM[1]} collapsed={collapsed} healthDot={healthDot} />
        </div>

        {/* Version */}
        {!collapsed && (
          <div className="px-4 py-2 border-t border-gray-800 text-[10px] text-gray-600 font-mono flex-shrink-0">
            v0.2 · schema 1.1.0
          </div>
        )}
      </aside>

      {/* ── Main content ── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <main id="main-content" className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>

      <CommandPalette />
      <ToastContainer />
    </div>
  );
}
