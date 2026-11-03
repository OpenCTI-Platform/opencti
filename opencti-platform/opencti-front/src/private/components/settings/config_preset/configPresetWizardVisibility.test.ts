import { describe, expect, it } from 'vitest';
import { shouldOpenConfigPresetWizard } from './configPresetWizardVisibility';

const base = { isBypass: true, isFeatureEnabled: true, isOptionEnabled: true, status: 'pending', isSkipped: false };

describe('shouldOpenConfigPresetWizard', () => {
  it('opens for a BYPASS user on a pending platform', () => {
    expect(shouldOpenConfigPresetWizard(base)).toBe(true);
    expect(shouldOpenConfigPresetWizard({ ...base, isSkipped: null })).toBe(true);
  });

  it('does not open when the user skipped it', () => {
    expect(shouldOpenConfigPresetWizard({ ...base, isSkipped: true })).toBe(false);
  });

  it.each(['completed', null, undefined])('does not open when the status is %s', (status) => {
    expect(shouldOpenConfigPresetWizard({ ...base, status, isSkipped: false })).toBe(false);
    expect(shouldOpenConfigPresetWizard({ ...base, status, isSkipped: true })).toBe(false);
  });

  it('does not open without BYPASS, without the flag or with the option off', () => {
    expect(shouldOpenConfigPresetWizard({ ...base, isBypass: false })).toBe(false);
    expect(shouldOpenConfigPresetWizard({ ...base, isFeatureEnabled: false })).toBe(false);
    expect(shouldOpenConfigPresetWizard({ ...base, isOptionEnabled: false })).toBe(false);
  });
});
