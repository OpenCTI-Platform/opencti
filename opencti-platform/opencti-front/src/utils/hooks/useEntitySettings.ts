import { useFragment } from 'react-relay';
import * as Yup from 'yup';
import { ObjectShape } from 'yup/lib/object';
import BaseSchema, { AnySchema } from 'yup/lib/schema';
import useAuth from './useAuth';
import { entitySettingsFragment } from '../../private/components/settings/sub_types/EntitySetting';
import { EntitySettingConnection_entitySettings$data, EntitySettingConnection_entitySettings$key } from '../../private/components/settings/sub_types/__generated__/EntitySettingConnection_entitySettings.graphql';
import { useFormatter } from '../../components/i18n';
import {
  AttributeConfiguration,
} from '../../private/components/settings/sub_types/EntitySettingAttributesConfiguration';

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

const useAttributesConfiguration = (id: string): AttributeConfiguration[] | null => {
  const entitySetting = useEntitySettings(id)[0];
  if (!entitySetting || !entitySetting.attributes_configuration) {
    return null;
  }
  return JSON.parse(entitySetting.attributes_configuration);
};

export const useYupSchemaBuilder = <TNextShape extends ObjectShape>(id: string, existingShape: TNextShape, exclusions?: string[]): BaseSchema => {
  const { t } = useFormatter();

  const attributesConfiguration = useAttributesConfiguration(id);
  if (!attributesConfiguration) {
    return Yup.object().shape(existingShape);
  }

  const existingKeys = Object.keys(existingShape);

  const newShape = Object.fromEntries(
    attributesConfiguration
      .filter((attr: AttributeConfiguration) => !(exclusions ?? []).includes(attr.name))
      .filter((attr: AttributeConfiguration) => attr.mandatory)
      .map((attr: AttributeConfiguration) => attr.name)
      .map((attrName: string) => {
        let validator;
        if (existingKeys.includes(attrName)) {
          validator = (existingShape[attrName] as AnySchema)
            .transform((v) => (!v || (Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t('This field is required'));
        } else {
          validator = Yup.mixed()
            .transform((v) => (!v || (Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t('This field is required'));
        }
        return [attrName, validator];
      }),
  );
  return Yup.object().shape({
    ...existingShape,
    ...newShape,
  });
};

export default useEntitySettings;
