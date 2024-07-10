import useAuth from './useAuth';
import { defaultConfiguration, OverviewLayoutCustomizationSettingsConfigurationParameters } from '../overviewLayoutCustomization';
import useHelper from './useHelper';

const useOverviewLayoutCustomization: (entityType: string) => Map<string, OverviewLayoutCustomizationSettingsConfigurationParameters> = (entityType) => {
  const { isFeatureEnable } = useHelper();
  const isFeatureFlagDisabled = !isFeatureEnable('OVERVIEW_LAYOUT_CUSTOMIZATION');
  if (isFeatureFlagDisabled) {
    return defaultConfiguration;
  }

  const { overviewLayoutCustomization } = useAuth();
  return overviewLayoutCustomization?.get(entityType) ?? defaultConfiguration;
};

export default useOverviewLayoutCustomization;
