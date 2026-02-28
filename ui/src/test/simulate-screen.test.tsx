import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import SimulateScreen from '@/features/simulate/SimulateScreen';

function renderSimulate() {
  return render(
    <MemoryRouter initialEntries={['/simulate']}>
      <Routes>
        <Route path="/simulate" element={<SimulateScreen />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('SimulateScreen', () => {
  it('supports offline and live scenario views', () => {
    renderSimulate();
    expect(screen.getByText(/offline scenarios/i)).toBeInTheDocument();
    expect(screen.getByText('Encoded PowerShell Download Cradle')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Live' }));
    expect(screen.getByText(/live scenarios - execute runs and validate detections/i)).toBeInTheDocument();
    expect(screen.getByText('Live Online Alert Recognition')).toBeInTheDocument();
    expect(screen.getByText('Live: LOLBin C2 Execution')).toBeInTheDocument();
  });
});
