import { useFragment } from 'react-relay';
import useAuth from './useAuth';
import { entitySettingsFragment } from '../../private/components/settings/sub_types/EntitySetting';
import { EntitySettingConnection_entitySettings$data, EntitySettingConnection_entitySettings$key } from '../../private/components/settings/sub_types/__generated__/EntitySettingConnection_entitySettings.graphql';

export type EntitySetting = EntitySettingConnection_entitySettings$data['edges'][0]['node'];

const useEntitySettings = (entityType?: string | string[]): EntitySetting[] => {
  const { entitySettings } = useAuth();

  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];

  return useFragment<EntitySettingConnection_entitySettings$key>(entitySettingsFragment, entitySettings)
    .edges
    .map(({ node }) => node)
    .filter(({ target_type }) => (entityType ? entityTypes.includes(target_type) : true));
};

export const useIsHiddenEntities = (...types: string[]): boolean => {
  return useEntitySettings(types)
    .filter((node) => node.platform_hidden_type !== null)
    .every((node) => node.platform_hidden_type);
};

export const useIsHiddenEntity = (id: string): boolean => {
  return useEntitySettings(id).some((node) => node.platform_hidden_type !== null && node.platform_hidden_type);
};

export const useIsEnforceReference = (id: string): boolean => {
  return useEntitySettings(id).some((node) => node.enforce_reference !== null && node.enforce_reference);
};

export default useEntitySettings;
