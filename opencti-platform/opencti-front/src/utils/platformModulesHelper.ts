import { RootPrivateQuery$data } from '../private/__generated__/RootPrivateQuery.graphql';

export const DISABLE_MANAGER_MESSAGE = 'To use this feature, your platform administrator must enable the according manager in the config.';

export const RUNTIME_SORTING = 'RUNTIME_SORTING';

export const SUBSCRIPTION_MANAGER = 'SUBSCRIPTION_MANAGER';
export const RULE_ENGINE = 'RULE_ENGINE';
export const HISTORY_MANAGER = 'HISTORY_MANAGER';
export const TASK_MANAGER = 'TASK_MANAGER';
export const EXPIRATION_SCHEDULER = 'EXPIRATION_SCHEDULER';
export const SYNC_MANAGER = 'SYNC_MANAGER';
export const RETENTION_MANAGER = 'RETENTION_MANAGER';

export interface ModuleHelper {
  isModuleEnable: (id: string) => boolean;
  isFeatureEnable: (id: string) => boolean;
  isRuntimeFieldEnable: () => boolean;
  isRuleEngineEnable: () => boolean;
  isTasksManagerEnable: () => boolean;
  isSyncManagerEnable: () => boolean;
  isRetentionManagerEnable: () => boolean;
  generateDisableMessage: (manager: string) => string;
}

const isFeatureEnable = (
  settings: RootPrivateQuery$data['settings'],
  id: string,
) => {
  const flags = settings.platform_feature_flags ?? [];
  const feature = flags.find((f) => f.id === id);
  return feature !== undefined && feature.enable === true;
};

const isModuleEnable = (
  settings: RootPrivateQuery$data['settings'],
  id: string,
) => {
  const modules = settings.platform_modules || [];
  const module = modules.find((f) => f.id === id);
  return module !== undefined && module.enable === true;
};

const platformModuleHelper = (
  settings: RootPrivateQuery$data['settings'],
): ModuleHelper => ({
  isModuleEnable: (id: string) => isModuleEnable(settings, id),
  isFeatureEnable: (id: string) => isFeatureEnable(settings, id),
  isRuleEngineEnable: () => isModuleEnable(settings, RULE_ENGINE),
  isRuntimeFieldEnable: () => isFeatureEnable(settings, RUNTIME_SORTING),
  isTasksManagerEnable: () => isModuleEnable(settings, TASK_MANAGER),
  isSyncManagerEnable: () => isModuleEnable(settings, SYNC_MANAGER),
  isRetentionManagerEnable: () => isModuleEnable(settings, RETENTION_MANAGER),
  generateDisableMessage: (id: string) => (!isModuleEnable(settings, id) ? DISABLE_MANAGER_MESSAGE : ''),
});

export default platformModuleHelper;
