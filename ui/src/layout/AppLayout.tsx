import React, { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { ToastContainer } from '@/components';
import { useRunsStore, useSettingsStore } from '@/stores';

const NAV_LEFT_STATIC = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/new-run', label: 'New Run' },
  { to: '/runs', label: 'Runs' },
  { to: '/alerts', label: 'Alerts' },
];

const NAV_LEFT = [
  ...NAV_LEFT_STATIC.slice(0, 3),
  { to: '/cases', label: 'Cases' },
  ...NAV_LEFT_STATIC.slice(3),
];

const NAV_RIGHT = [
  { to: '/simulate', label: 'Simulate' },
  { to: '/settings', label: 'Settings' },
];

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-3 py-1.5 text-sm font-medium rounded-md transition-colors
         ${isActive
           ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
           : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'}`
      }
    >
      {label}
    </NavLink>
  );
}

export function AppLayout() {
  const { runs, fetchRuns } = useRunsStore();
  const display = useSettingsStore((s) => s.display);
  const [systemTheme, setSystemTheme] = useState<'dark' | 'light'>('dark');
  const hasFetched = useRef(false);

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

  const activeTheme = display.theme === 'system' ? systemTheme : display.theme;
  const location = useLocation();

  // Set document title per route
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

  return (
    <div className="min-h-screen flex flex-col bg-gray-950 text-gray-100">
      {/* Skip to main content link for keyboard/screen reader users */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:px-4 focus:py-2 focus:bg-blue-600 focus:text-white focus:rounded-md focus:text-sm focus:font-medium"
      >
        Skip to main content
      </a>

      <header className="flex-shrink-0 bg-gray-900/80 backdrop-blur-sm border-b border-gray-800 px-4 py-0 sticky top-0 z-40">
        <div className="flex items-center h-12">
          <NavLink to="/dashboard" className="flex items-center gap-2 mr-6 group">
            <span className="text-blue-400 font-bold text-base group-hover:text-blue-300 transition-colors">W</span>
            <span className="font-semibold text-sm text-gray-200 hidden md:inline">Wazuh Sysmon Triage</span>
            <span className="font-semibold text-sm text-gray-200 md:hidden">WST</span>
          </NavLink>

          <nav className="flex items-center gap-1 h-full" aria-label="Main navigation">
            {NAV_LEFT.map((item) => (
              <NavItem key={`${item.label}-${item.to}`} {...item} />
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-1">
            {NAV_RIGHT.map((item) => (
              <NavItem key={`${item.label}-${item.to}`} {...item} />
            ))}
            <div className="w-px h-5 bg-gray-800 mx-2" />
            <span className="text-xs text-gray-600 font-mono">v0.2</span>
          </div>
        </div>
      </header>

      <main id="main-content" className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>

      <footer className="flex-shrink-0 border-t border-gray-900 px-4 py-2 flex items-center justify-between text-[10px] text-gray-600">
        <span>Wazuh Sysmon Triage</span>
        <span>Schema v1.1.0 | {new Date().getFullYear()}</span>
      </footer>

      <ToastContainer />
    </div>
  );
}
