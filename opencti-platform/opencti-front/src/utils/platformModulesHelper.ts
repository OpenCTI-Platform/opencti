import { RootSettings$data } from '../private/__generated__/RootSettings.graphql';

export const DISABLE_MANAGER_MESSAGE = 'To use this feature, your platform administrator must enable the according manager in the config.';

export const RUNTIME_SORTING = 'RUNTIME_SORTING';

export const SUBSCRIPTION_MANAGER = 'SUBSCRIPTION_MANAGER';
export const RULE_ENGINE = 'RULE_ENGINE';
export const HISTORY_MANAGER = 'HISTORY_MANAGER';
export const TASK_MANAGER = 'TASK_MANAGER';
export const EXPIRATION_SCHEDULER = 'EXPIRATION_SCHEDULER';
export const SYNC_MANAGER = 'SYNC_MANAGER';
export const INGESTION_MANAGER = 'INGESTION_MANAGER';
export const FILE_INDEX_MANAGER = 'FILE_INDEX_MANAGER';
export const RETENTION_MANAGER = 'RETENTION_MANAGER';
export const PLAYBOOK_MANAGER = 'PLAYBOOK_MANAGER';
export const INDICATOR_DECAY_MANAGER = 'INDICATOR_DECAY_MANAGER';
export const TELEMETRY_MANAGER = 'TELEMETRY_MANAGER';
export const GARBAGE_COLLECTION_MANAGER = 'GARBAGE_COLLECTION_MANAGER';

export interface ModuleHelper {
  isModuleEnable: (id: string) => boolean;
  isModuleWarning: (id: string) => boolean;
  isFeatureEnable: (id: string) => boolean;
  isRuntimeFieldEnable: () => boolean;
  isRuleEngineEnable: () => boolean;
  isPlayBookManagerEnable: () => boolean;
  isTasksManagerEnable: () => boolean;
  isSyncManagerEnable: () => boolean;
  isRetentionManagerEnable: () => boolean;
  isIngestionManagerEnable: () => boolean;
  isFileIndexManagerEnable: () => boolean;
  isIndicatorDecayManagerEnable: () => boolean;
  isTelemetryManagerEnable: () => boolean;
  isTrashEnable: () => boolean;
  isPlaygroundEnable: () => boolean;
  generateDisableMessage: (manager: string) => string;
  isRequestAccessEnabled: () => boolean;
  isChatbotAiEnabled: () => boolean;
}

export const isFeatureEnable = (
  settings: RootSettings$data,
  id: string,
) => {
  const flags = settings.platform_feature_flags ?? [];
  // config can target all FF available with special FF id "*"
  if (flags.find((f) => f.id === '*' && f.enable)) {
    return true;
  }
  return flags.some((flag) => flag.id === id && flag.enable);
};

const isModuleEnable = (
  settings: RootSettings$data,
  id: string,
) => {
  const modules = settings.platform_modules || [];
  return modules.some((module) => module.id === id && module.enable);
};

const isModuleWarning = (
  settings: RootSettings$data,
  id: string,
) => {
  const modules = settings.platform_modules || [];
  return modules.some((module) => module.id === id && module.warning);
};

const platformModuleHelper = (
  settings: RootSettings$data,
): ModuleHelper => ({
  isModuleEnable: (id: string) => isModuleEnable(settings, id),
  isModuleWarning: (id: string) => isModuleWarning(settings, id),
  isFeatureEnable: (id: string) => isFeatureEnable(settings, id),
  isRuleEngineEnable: () => isModuleEnable(settings, RULE_ENGINE),
  isRuntimeFieldEnable: () => isFeatureEnable(settings, RUNTIME_SORTING),
  isTasksManagerEnable: () => isModuleEnable(settings, TASK_MANAGER),
  isSyncManagerEnable: () => isModuleEnable(settings, SYNC_MANAGER),
  isPlayBookManagerEnable: () => isModuleEnable(settings, PLAYBOOK_MANAGER),
  isRetentionManagerEnable: () => isModuleEnable(settings, RETENTION_MANAGER),
  isIngestionManagerEnable: () => isModuleEnable(settings, INGESTION_MANAGER),
  isFileIndexManagerEnable: () => isModuleEnable(settings, FILE_INDEX_MANAGER),
  isIndicatorDecayManagerEnable: () => isModuleEnable(settings, INDICATOR_DECAY_MANAGER),
  isTelemetryManagerEnable: () => isModuleEnable(settings, TELEMETRY_MANAGER),
  isTrashEnable: () => settings.platform_trash_enabled,
  isPlaygroundEnable: () => settings.playground_enabled,
  generateDisableMessage: (id: string) => (!isModuleEnable(settings, id) ? DISABLE_MANAGER_MESSAGE : ''),
  isRequestAccessEnabled: () => settings.request_access_enabled,
  isChatbotAiEnabled: () => settings.filigran_chatbot_ai_cgu_status === 'enabled',
});

export default platformModuleHelper;
