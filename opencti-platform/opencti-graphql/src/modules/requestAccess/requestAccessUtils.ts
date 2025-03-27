import type { AuthContext, AuthUser } from '../../types/user';
import { isFeatureEnabled, logApp } from '../../config/conf';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import type { BasicStoreSettings } from '../../types/settings';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';

export const verifyRequestAccessEnabled = async (context: AuthContext, user: AuthUser, settings: BasicStoreSettings, rfiEntitySettings: BasicStoreEntityEntitySetting) => {
  let message = '';
  if (!isFeatureEnabled('ORGA_SHARING_REQUEST_FF')) {
    return { enabled: false };
  }
  // 1. EE must be enabled
  const isEEConfigured: boolean = await isEnterpriseEdition(context);
  if (!isEEConfigured) {
    message += 'Enterprise edition must be enabled.';
  }
  // 2. Platform organization should be set up
  const platformOrgValue = settings.platform_organization;
  const isPlatformOrgSetup: boolean = platformOrgValue !== undefined && platformOrgValue !== '';
  if (!isPlatformOrgSetup) {
    message += 'Platform organization must be setup.';
  }

  // 3. Request access status should be configured
  const areRequestAccessStatusConfigured: boolean = rfiEntitySettings?.request_access_workflow !== undefined
    && rfiEntitySettings.request_access_workflow.declined_workflow_id !== undefined
    && rfiEntitySettings.request_access_workflow.approved_workflow_id !== undefined;
  if (!areRequestAccessStatusConfigured) {
    message += 'RFI status for decline and approval must be configured in entity settings.';
  }

  // 4. At least one auth member admin should be configured.
  const isRequestAccesApprovalAdminConfigured: boolean = rfiEntitySettings?.request_access_workflow?.approval_admin !== undefined
    && rfiEntitySettings?.request_access_workflow?.approval_admin.length >= 1;
  if (!isRequestAccesApprovalAdminConfigured) {
    message += 'At least one approval administrator must be configured in entity settings.';
  }

  const isEnabled: boolean = isEEConfigured
    && isPlatformOrgSetup
    && areRequestAccessStatusConfigured
    && isRequestAccesApprovalAdminConfigured;

  return {
    enabled: isEnabled,
    message
  };
};

// This one has no dependency on request access domain and can be use in middleware
export const isRequestAccessEnabled = async (context: AuthContext, user: AuthUser, settings: BasicStoreSettings, rfiEntitySettings: BasicStoreEntityEntitySetting) => {
  const result = await verifyRequestAccessEnabled(context, user, settings, rfiEntitySettings);
  logApp.info('[REQUEST ACCESS] Request access enabled: ', { result });
  return result.enabled === true;
};
