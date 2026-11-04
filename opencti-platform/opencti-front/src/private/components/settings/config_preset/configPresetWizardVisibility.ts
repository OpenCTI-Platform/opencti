export interface ConfigPresetWizardVisibilityInput {
  isBypass: boolean;
  isFeatureEnabled: boolean;
  // Config option app:bootstrap_wizard:enabled
  isOptionEnabled: boolean;
  // platform_bootstrap_status of the settings, null on an existing platform
  status: string | null | undefined;
  // bootstrap_wizard_skipped of the user
  isSkipped: boolean | null | undefined;
}

// The wizard opens by itself on a new platform, for a BYPASS user who has not skipped it
export const shouldOpenConfigPresetWizard = ({ isBypass, isFeatureEnabled, isOptionEnabled, status, isSkipped }: ConfigPresetWizardVisibilityInput) => {
  return isBypass && isFeatureEnabled && isOptionEnabled && status === 'pending' && !isSkipped;
};
