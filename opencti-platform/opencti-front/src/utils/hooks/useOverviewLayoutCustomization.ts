import { useMemo } from 'react';
import { useFragment } from 'react-relay';
import { entitySettingsFragment } from '@components/settings/sub_types/entity_setting/EntitySettingsFragment';
import useAuth from './useAuth';
import { EntitySettingsFragment_entitySetting$key } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingsFragment_entitySetting.graphql';

type OverviewWidgetLayout = { key: string; width: number; label: string };

// A widget hidden in the overview layout customization keeps its place in the layout with this width
export const HIDDEN_OVERVIEW_WIDGET_WIDTH = 0;

const useOverviewLayoutCustomization: (entityType: string) => OverviewWidgetLayout[] = (entityType) => {
  const { entitySettings } = useAuth();
  const entitySettingsData = entitySettings?.edges?.map((setting) => (
    useFragment<EntitySettingsFragment_entitySetting$key>(entitySettingsFragment, setting.node)));

  const overviewLayoutCustomization = useMemo(() => {
    const overviewLayoutCustomizationEntries = entitySettingsData
      ?.map(({ target_type, overview_layout_customization }) => ({ key: target_type, values: overview_layout_customization }))
      .filter((entry) => !!entry.values)
      .map(({ key: entityTypeKey, values: widgetsValues }) => [entityTypeKey, widgetsValues]);
    const overviewLayoutCustomizations = overviewLayoutCustomizationEntries
      ? new Map(overviewLayoutCustomizationEntries.map(([key, values]) => [key, values]))
      : new Map();
    const layout: OverviewWidgetLayout[] = overviewLayoutCustomizations.get(entityType) ?? [];
    return layout.filter(({ width }) => width !== HIDDEN_OVERVIEW_WIDGET_WIDTH);
  }, [entitySettingsData, entityType]);

  return overviewLayoutCustomization;
};

export default useOverviewLayoutCustomization;
