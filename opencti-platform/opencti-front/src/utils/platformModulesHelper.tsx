import { createContext, PropsWithChildren, ReactNode, useContext, useMemo } from 'react';
import { graphql, useFragment } from 'react-relay';
import { platformModulesHelper_settings$data, platformModulesHelper_settings$key } from './__generated__/platformModulesHelper_settings.graphql';

export const DISABLE_MANAGER_MESSAGE = 'To use this feature, your platform administrator must enable the according manager in the config.';

export const RUNTIME_SORTING = 'RUNTIME_SORTING';

export const ACTIVITY_HISTORY_RETENTION = 'ACTIVITY_HISTORY_RETENTION';

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
export const TIPTAP_EDITOR = 'TIPTAP_EDITOR';

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
  isTiptapEditorEnable: () => boolean;
  isActivityHistoryRetentionEnable: () => boolean;
}

export const isFeatureEnable = (
  settings: platformModulesHelper_settings$data['settings'],
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
  settings: platformModulesHelper_settings$data['settings'],
  id: string,
) => {
  const modules = settings.platform_modules || [];
  return modules.some((module) => module.id === id && module.enable);
};

const isModuleWarning = (
  settings: platformModulesHelper_settings$data['settings'],
  id: string,
) => {
  const modules = settings.platform_modules || [];
  return modules.some((module) => module.id === id && module.warning);
};

const platformModuleHelper = (
  settings: platformModulesHelper_settings$data['settings'],
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
  isTiptapEditorEnable: () => isFeatureEnable(settings, TIPTAP_EDITOR),
  isActivityHistoryRetentionEnable: () => isFeatureEnable(settings, ACTIVITY_HISTORY_RETENTION),
});

const platformModulesHelperFragment = graphql`
  fragment platformModulesHelper_settings on Query {
    settings {
      platform_modules {
        id
        enable
        warning
      }
      platform_feature_flags {
        id
        enable
      }
      platform_trash_enabled
      playground_enabled
      request_access_enabled
      filigran_chatbot_ai_cgu_status
    }
  }
`;

export interface PlatformModulesHelperPreloadedDataContext {
  preloadedData: platformModulesHelper_settings$key | undefined;
}

const defaultContext = {
  preloadedData: undefined,
};

export const PlatformModulesHelperPreloadedDataContext = createContext<PlatformModulesHelperPreloadedDataContext>(defaultContext);

type PlatformModulesHelperPreloadedDataContextProviderProps = PropsWithChildren<{
  preloadedData: platformModulesHelper_settings$key;
}>;

export const PlatformModulesHelperPreloadedDataContextProvider = (
  { preloadedData, children }: PlatformModulesHelperPreloadedDataContextProviderProps,
) => {
  const value = useMemo(() => ({ preloadedData }), [preloadedData]);
  return (
    <PlatformModulesHelperPreloadedDataContext.Provider value={value}>
      {children}
    </PlatformModulesHelperPreloadedDataContext.Provider>
  );
};

interface PlatformModulesHelperPreloadedDataContextConsumerProps {
  render: (props: ReturnType<typeof usePlatformModulesHelper>) => ReactNode;
}

/**
 * @deprecated Should be used only when required (i.e. in Class Components)
 * Use useSchema instead in Functional Components.
 */
export const PlatformModulesHelperPreloadedDataContextConsumer = ({ render }: PlatformModulesHelperPreloadedDataContextConsumerProps) => {
  return render(usePlatformModulesHelper());
};

export const usePlatformModulesHelper = () => {
  const { preloadedData } = useContext(PlatformModulesHelperPreloadedDataContext);
  const data = useFragment<
    platformModulesHelper_settings$key
  >(platformModulesHelperFragment, preloadedData);
  if (!data) {
    throw new Error('No data for platformModuleHelper');
  }
  return platformModuleHelper(data.settings);
};

export default platformModuleHelper;
