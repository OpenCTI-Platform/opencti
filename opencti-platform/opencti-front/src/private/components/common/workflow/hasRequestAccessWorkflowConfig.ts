export interface SubTypeWithRequestAccessSettings {
  settings: {
    availableSettings: readonly string[];
    requestAccessConfiguration?: unknown | null;
  };
}

/**
 * RequestAccess workflow configuration is only usable when EE is active, the entity type's
 * `availableSettings` allow-list includes `request_access_workflow`, and a RequestAccess
 * configuration has actually been set up (matches the gate `GlobalWorkflowSettingsCard` uses).
 */
export const hasRequestAccessWorkflowConfig = (
  subType: SubTypeWithRequestAccessSettings,
  isEnterpriseEdition: boolean,
): boolean => isEnterpriseEdition
  && subType.settings.availableSettings.includes('request_access_workflow')
  && !!subType.settings.requestAccessConfiguration;
