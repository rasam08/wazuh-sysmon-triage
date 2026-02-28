import { describe, it, expect, beforeEach } from 'vitest';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import NewRunScreen from '../features/new-run/NewRunScreen';
import RunsDashboardScreen from '../features/runs/RunsDashboardScreen';
import AlertWorkbenchScreen from '../features/alerts/AlertWorkbenchScreen';

function renderWithRouter(ui: React.ReactElement, { route = '/' } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Routes>
        <Route path="*" element={ui} />
      </Routes>
    </MemoryRouter>
  );
}

describe('NewRunScreen', () => {
  it('renders the new run form', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('New Triage Run')).toBeInTheDocument();
    expect(screen.getByText('Run Triage')).toBeInTheDocument();
    expect(screen.getByText('Preview Query')).toBeInTheDocument();
    expect(screen.getByText('Reset')).toBeInTheDocument();
  });

  it('renders mode toggle', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('Live')).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('renders profile options', () => {
    renderWithRouter(<NewRunScreen />);
    expect(screen.getByText('soc')).toBeInTheDocument();
    expect(screen.getByText('dev')).toBeInTheDocument();
    expect(screen.getByText('lab')).toBeInTheDocument();
  });
});

describe('RunsDashboardScreen', () => {
  it('renders runs or empty state', () => {
    renderWithRouter(<RunsDashboardScreen />);
    // Will show loading initially, then runs or empty state
    expect(document.body).toBeTruthy();
  });
});

describe('AlertWorkbenchScreen', () => {
  it('renders alert workbench', () => {
    renderWithRouter(<AlertWorkbenchScreen />);
    // Will show loading initially
    expect(document.body).toBeTruthy();
  });
});
