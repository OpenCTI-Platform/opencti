import { RootPrivateQuery$data } from '../private/__generated__/RootPrivateQuery.graphql';

export interface ModuleHelper {
  isModuleEnable: (id: string) => boolean;
  isFeatureEnable: (id: string) => boolean;
  isRuntimeFieldEnable: () => boolean;
  isRuleEngineEnable: () => boolean;
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
  isRuleEngineEnable: () => isModuleEnable(settings, 'RULE_ENGINE'),
  isFeatureEnable: (id: string) => isFeatureEnable(settings, id),
  isRuntimeFieldEnable: () => isFeatureEnable(settings, 'RUNTIME_SORTING'),
});

export default platformModuleHelper;
