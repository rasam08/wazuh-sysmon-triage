const ONBOARDING_STORAGE_KEY = 'wst-onboarding-v1-complete';
export const ONBOARDING_RESET_EVENT = 'wst:onboarding-reset';

export function isOnboardingComplete(): boolean {
  if (typeof window === 'undefined') return true;
  try {
    return window.localStorage.getItem(ONBOARDING_STORAGE_KEY) === '1';
  } catch {
    return true;
  }
}

export function markOnboardingComplete(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(ONBOARDING_STORAGE_KEY, '1');
  } catch {
    // no-op
  }
}

export function resetOnboardingTour(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(ONBOARDING_STORAGE_KEY);
  } catch {
    // no-op
  }
}
