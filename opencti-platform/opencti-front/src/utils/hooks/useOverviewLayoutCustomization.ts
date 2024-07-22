import useAuth from './useAuth';
import { defaultConfiguration } from '../overviewLayoutCustomization';
import useHelper from './useHelper';

const useOverviewLayoutCustomization: (entityType: string) => Array<{ key: string, width: number }> = (entityType) => {
  const { isFeatureEnable } = useHelper();
  const isFeatureFlagDisabled = !isFeatureEnable('OVERVIEW_LAYOUT_CUSTOMIZATION');
  if (isFeatureFlagDisabled) {
    return Array.from(defaultConfiguration.entries())
      .flatMap(([key, width]) => ({ key, width }));
  }

  const { overviewLayoutCustomization } = useAuth();
  return Array.from(overviewLayoutCustomization?.get(entityType)?.entries() ?? defaultConfiguration.entries())
    .flatMap(([key, width]) => ({ key, width }));
};

export default useOverviewLayoutCustomization;
