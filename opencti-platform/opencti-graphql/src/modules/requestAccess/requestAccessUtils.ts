import { logApp } from '../../config/conf';
import type { BasicStoreSettings } from '../../types/settings';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';

export const verifyRequestAccessEnabled = (settings: BasicStoreSettings, rfiEntitySettings: BasicStoreEntityEntitySetting) => {
  const message: string [] = [];

  // 1. EE must be enabled
  const isEEConfigured: boolean = settings.valid_enterprise_edition === true;
  if (!isEEConfigured) {
    message.push('Enterprise edition must be enabled.');
  }
  // 2. Platform organization should be set up
  const platformOrgValue = settings.platform_organization;
  const isPlatformOrgSetup: boolean = platformOrgValue !== undefined && platformOrgValue !== '';
  if (!isPlatformOrgSetup) {
    message.push('Platform organization must be setup.');
  }

  // 3. Request access status should be configured
  const areRequestAccessStatusConfigured: boolean = rfiEntitySettings?.request_access_workflow !== undefined
    && rfiEntitySettings.request_access_workflow.declined_workflow_id !== undefined
    && rfiEntitySettings.request_access_workflow.approved_workflow_id !== undefined;
  if (!areRequestAccessStatusConfigured) {
    message.push('RFI status for decline and approval must be configured in entity settings.');
  }

  // 4. At least one auth member admin should be configured.
  const isRequestAccessApprovalAdminConfigured: boolean = rfiEntitySettings?.request_access_workflow?.approval_admin !== undefined
    && rfiEntitySettings?.request_access_workflow?.approval_admin.length >= 1;
  if (!isRequestAccessApprovalAdminConfigured) {
    message.push('At least one approval administrator must be configured in entity settings.');
  }

  const isEnabled: boolean = isEEConfigured
    && isPlatformOrgSetup
    && areRequestAccessStatusConfigured
    && isRequestAccessApprovalAdminConfigured;

  logApp.debug('Request access enabled result:', { enabled: isEnabled, message: message.join(' ') });

  return {
    enabled: isEnabled,
    message: message.join(' '),
  };
};

// This one has no dependency on request access domain and can be used in middleware
export const isRequestAccessEnabled = (settings: BasicStoreSettings, rfiEntitySettings: BasicStoreEntityEntitySetting) => {
  const result = verifyRequestAccessEnabled(settings, rfiEntitySettings);
  return result.enabled === true;
};
