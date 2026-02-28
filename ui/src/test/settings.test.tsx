import { describe, it, expect } from 'vitest';
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import SettingsScreen from '../features/settings/SettingsScreen';

function renderSettings() {
  return render(
    <MemoryRouter initialEntries={['/settings']}>
      <Routes>
        <Route path="/settings" element={<SettingsScreen />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('SettingsScreen', () => {
  it('renders the settings page with nav sections', () => {
    renderSettings();
    expect(screen.getByText('Settings')).toBeInTheDocument();
    expect(screen.getByText('API Endpoint')).toBeInTheDocument();
    expect(screen.getByText('Run Presets')).toBeInTheDocument();
    expect(screen.getByText('Alert Thresholds')).toBeInTheDocument();
    expect(screen.getByText('Notifications')).toBeInTheDocument();
    expect(screen.getByText('Theme & Display')).toBeInTheDocument();
    expect(screen.getByText('Run Allowlist')).toBeInTheDocument();
    expect(screen.getByText('Suppression Rules')).toBeInTheDocument();
    expect(screen.getByText('Export Config')).toBeInTheDocument();
  });

  it('shows API section by default', () => {
    renderSettings();
    expect(screen.getByText('API Endpoint Configuration')).toBeInTheDocument();
    expect(screen.getByText('Test URL Reachability')).toBeInTheDocument();
  });

  it('navigates between sections', () => {
    renderSettings();
    fireEvent.click(screen.getByText('Alert Thresholds'));
    expect(screen.getByText('Alert Threshold Tuning')).toBeInTheDocument();
  });

  it('navigates to notifications section', () => {
    renderSettings();
    fireEvent.click(screen.getByText('Notifications'));
    expect(screen.getByText('Notification Preferences')).toBeInTheDocument();
  });

  it('navigates to theme section', () => {
    renderSettings();
    fireEvent.click(screen.getByText('Theme & Display'));
    expect(screen.getByText('Theme & Display Options')).toBeInTheDocument();
  });

  it('navigates to export section', () => {
    renderSettings();
    fireEvent.click(screen.getByText('Export Config'));
    expect(screen.getByText('Export Format Configuration')).toBeInTheDocument();
  });

  it('navigates to run allowlist section', () => {
    renderSettings();
    fireEvent.click(screen.getByText('Run Allowlist'));
    expect(screen.getByText('Run-Time Detection Allowlist')).toBeInTheDocument();
    expect(screen.getByText('No custom run allowlist entries configured.')).toBeInTheDocument();
  });

  it('has export/import/reset buttons', () => {
    renderSettings();
    expect(screen.getByText('Export Settings')).toBeInTheDocument();
    expect(screen.getByText('Import Settings')).toBeInTheDocument();
    expect(screen.getByText('Reset All')).toBeInTheDocument();
  });
});
