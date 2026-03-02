import React, { Suspense, lazy } from 'react';
import { createBrowserRouter, Navigate } from 'react-router-dom';
import { AppLayout } from '@/layout/AppLayout';
import { LoadingSpinner, RouteErrorFallback } from '@/components';

const DashboardScreen = lazy(() => import('@/features/dashboard/DashboardScreen'));
const NewRunScreen = lazy(() => import('@/features/new-run/NewRunScreen'));
const RunsDashboardScreen = lazy(() => import('@/features/runs/RunsDashboardScreen'));
const CaseOverviewScreen = lazy(() => import('@/features/cases/CaseOverviewScreen'));
const CaseListScreen = lazy(() => import('@/features/cases/CaseListScreen'));
const AlertWorkbenchScreen = lazy(() => import('@/features/alerts/AlertWorkbenchScreen'));
const SimulateScreen = lazy(() => import('@/features/simulate/SimulateScreen'));
const SettingsScreen = lazy(() => import('@/features/settings/SettingsScreen'));
const NotFoundScreen = lazy(() => import('@/features/not-found/NotFoundScreen'));

function withSuspense(element: React.ReactElement) {
  return (
    <Suspense fallback={<LoadingSpinner label="Loading screen..." />}>
      {element}
    </Suspense>
  );
}

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    errorElement: <RouteErrorFallback />,
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: withSuspense(<DashboardScreen />) },
      { path: 'new-run', element: withSuspense(<NewRunScreen />) },
      { path: 'runs', element: withSuspense(<RunsDashboardScreen />) },
      { path: 'cases', element: withSuspense(<CaseListScreen />) },
      { path: 'cases/:caseId', element: withSuspense(<CaseOverviewScreen />) },
      { path: 'alerts/:alertId', element: withSuspense(<AlertWorkbenchScreen />) },
      { path: 'alerts', element: withSuspense(<AlertWorkbenchScreen />) },
      { path: 'simulate', element: withSuspense(<SimulateScreen />) },
      { path: 'settings', element: withSuspense(<SettingsScreen />) },
      { path: '*', element: withSuspense(<NotFoundScreen />) },
    ],
  },
]);
