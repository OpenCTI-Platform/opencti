import { useFragment } from 'react-relay';
import useAuth from './useAuth';
import {
  entitySettingFragment,
  entitySettingsFragment,
} from '../../private/components/settings/sub_types/EntitySetting';
import {
  EntitySetting_entitySetting$data,
} from '../../private/components/settings/sub_types/__generated__/EntitySetting_entitySetting.graphql';
import {
  EntitySettingConnection_entitySettings$data,
} from '../../private/components/settings/sub_types/__generated__/EntitySettingConnection_entitySettings.graphql';

const useEntitySettings = () => {
  const { entitySettings } = useAuth();
  return useFragment(entitySettingsFragment, entitySettings) as EntitySettingConnection_entitySettings$data;
};

export const useIsHiddenEntities = (...ids: string[]): boolean => {
  return useEntitySettings().edges.map((edgeNode) => edgeNode.node)
    .map((node) => useFragment(entitySettingFragment, node) as EntitySetting_entitySetting$data)
    .filter((node) => ids.includes(node.target_type) && node.platform_hidden_type !== null)
    .every((node) => node.platform_hidden_type);
};

export const useIsHiddenEntity = (id: string): boolean => {
  return useEntitySettings().edges.map((edgeNode) => edgeNode.node)
    .map((node) => useFragment(entitySettingFragment, node) as EntitySetting_entitySetting$data)
    .some((node) => id === node.target_type && node.platform_hidden_type !== null && node.platform_hidden_type);
};

export const useIsEnforceReference = (id: string): boolean => {
  return useEntitySettings().edges.map((edgeNode) => edgeNode.node)
    .map((node) => useFragment(entitySettingFragment, node) as EntitySetting_entitySetting$data)
    .some((node) => id === node.target_type && node.enforce_reference !== null && node.enforce_reference);
};

export default useEntitySettings;
