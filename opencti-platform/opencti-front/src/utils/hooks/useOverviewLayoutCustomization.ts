import { useMemo } from 'react';
import { useFragment } from 'react-relay';
import { EntitySettingSettings_entitySetting$key } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingSettings_entitySetting.graphql';
import { entitySettingFragment } from '@components/settings/sub_types/entity_setting/EntitySettingSettings';
import useAuth from './useAuth';

type OverviewWidgetLayout = { key: string, width: number, label: string };

const useOverviewLayoutCustomization: (entityType: string) => OverviewWidgetLayout[] = (entityType) => {
  const { entitySettings } = useAuth();
  const entitySettingsData = entitySettings?.edges?.map((setting) => (
    useFragment<EntitySettingSettings_entitySetting$key>(entitySettingFragment, setting.node)));

  const overviewLayoutCustomization = useMemo(() => {
    const overviewLayoutCustomizationEntries = entitySettingsData
      ?.map(({ target_type, overview_layout_customization }) => ({ key: target_type, values: overview_layout_customization }))
      .filter((entry) => !!entry.values)
      .map(({ key: entityTypeKey, values: widgetsValues }) => [entityTypeKey, widgetsValues]);
    const overviewLayoutCustomizations = overviewLayoutCustomizationEntries
      ? new Map(overviewLayoutCustomizationEntries.map(([key, values]) => [key, values]))
      : new Map();
    return overviewLayoutCustomizations.get(entityType) ?? [];
  }, [entitySettingsData, entityType]);

  return overviewLayoutCustomization;
};

export default useOverviewLayoutCustomization;
