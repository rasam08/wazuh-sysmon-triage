import React from 'react';
import { Button } from './Button';

interface OnboardingTourProps {
  open: boolean;
  onDismiss: () => void;
  onStartRun: () => void;
}

const STEPS = [
  {
    title: 'Create a Run',
    detail: 'Open New Run to choose profile, time window, and score threshold.',
  },
  {
    title: 'Track Progress',
    detail: 'Watch queue, stage, and runtime status in the Runs dashboard.',
  },
  {
    title: 'Investigate Alerts',
    detail: 'Use Alert Workbench filters, pivots, and bundle context to triage quickly.',
  },
  {
    title: 'Tune Rules',
    detail: 'Adjust thresholds, suppression, and display settings for your environment.',
  },
];

export function OnboardingTour({ open, onDismiss, onStartRun }: OnboardingTourProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center px-4" role="dialog" aria-modal="true" aria-label="Onboarding tour">
      <div className="absolute inset-0 bg-gray-950/80" onClick={onDismiss} aria-hidden="true" />
      <div className="relative w-full max-w-2xl rounded-xl border border-gray-700 bg-gray-900 shadow-2xl">
        <div className="border-b border-gray-800 px-6 py-4">
          <h2 className="text-lg font-semibold text-gray-100">Welcome to Wazuh Sysmon Triage</h2>
          <p className="mt-1 text-sm text-gray-400">Quick start checklist for first-time setup.</p>
        </div>
        <ol className="space-y-3 px-6 py-5">
          {STEPS.map((step, idx) => (
            <li key={step.title} className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/80 px-3 py-2.5">
              <span className="mt-0.5 inline-flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-blue-600/25 text-xs font-semibold text-blue-300">
                {idx + 1}
              </span>
              <div>
                <p className="text-sm font-medium text-gray-200">{step.title}</p>
                <p className="text-xs text-gray-400">{step.detail}</p>
              </div>
            </li>
          ))}
        </ol>
        <div className="flex items-center justify-end gap-2 border-t border-gray-800 px-6 py-4">
          <Button size="sm" variant="ghost" onClick={onDismiss}>Skip Tour</Button>
          <Button size="sm" onClick={onStartRun}>Start First Run</Button>
        </div>
      </div>
    </div>
  );
}
