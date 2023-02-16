import { useFragment } from 'react-relay';
import * as Yup from 'yup';
import { ObjectShape } from 'yup/lib/object';
import BaseSchema, { AnySchema } from 'yup/lib/schema';
import useAuth from './useAuth';
import { entitySettingsFragment } from '../../private/components/settings/sub_types/EntitySetting';
import {
  EntitySettingConnection_entitySettings$data,
  EntitySettingConnection_entitySettings$key,
} from '../../private/components/settings/sub_types/__generated__/EntitySettingConnection_entitySettings.graphql';
import { useFormatter } from '../../components/i18n';

export type EntitySetting =
  EntitySettingConnection_entitySettings$data['edges'][0]['node'];

const useEntitySettings = (entityType?: string | string[]): EntitySetting[] => {
  const { entitySettings } = useAuth();
  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];
  return useFragment<EntitySettingConnection_entitySettings$key>(
    entitySettingsFragment,
    entitySettings,
  )
    .edges.map(({ node }) => node)
    .filter(({ target_type }) => (entityType ? entityTypes.includes(target_type) : true));
};

export const useIsHiddenEntities = (...types: string[]): boolean => {
  const { me } = useAuth();
  return useEntitySettings(types)
    .filter((node) => node.platform_hidden_type !== null)
    .every((node) => node.platform_hidden_type || me.default_hidden_types.includes(node.target_type));
};

export const useIsHiddenEntity = (id: string): boolean => {
  const { me } = useAuth();
  return useEntitySettings(id).some((node) => node.platform_hidden_type !== null
    && (node.platform_hidden_type || me.default_hidden_types.includes(node.target_type)));
};

export const useIsEnforceReference = (id: string): boolean => {
  return useEntitySettings(id).some(
    (node) => node.enforce_reference !== null && node.enforce_reference,
  );
};

export const useYupSchemaBuilder = <TNextShape extends ObjectShape>(
  id: string,
  existingShape: TNextShape,
  isCreation: boolean,
  exclusions?: string[],
): BaseSchema => {
  const { t } = useFormatter();
  const entitySettings = useEntitySettings(id).at(0);
  if (!entitySettings) {
    throw Error(`Invalid type for setting: ${id}`);
  }
  const mandatoryAttributes = [...entitySettings.mandatoryAttributes];
  // In creation, if enforce_reference is activated, externalReferences is required
  if (isCreation && entitySettings.enforce_reference === true) {
    mandatoryAttributes.push('externalReferences');
  }
  const existingKeys = Object.keys(existingShape);
  const newShape = Object.fromEntries(
    mandatoryAttributes
      .filter((attr) => !(exclusions ?? []).includes(attr))
      .map((attrName: string) => {
        if (existingKeys.includes(attrName)) {
          const validator = (existingShape[attrName] as AnySchema)
            .transform((v) => (!v || (Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t('This field is required'));
          return [attrName, validator];
        }
        const validator = Yup.mixed()
          .transform((v) => (!v || (Array.isArray(v) && v.length === 0) ? undefined : v))
          .required(t('This field is required'));
        return [attrName, validator];
      }),
  );
  return Yup.object().shape({ ...existingShape, ...newShape });
};

export const useSchemaCreationValidation = <TNextShape extends ObjectShape>(
  id: string,
  existingShape: TNextShape,
  exclusions?: string[],
): BaseSchema => {
  return useYupSchemaBuilder(id, existingShape, true, exclusions);
};

export const useSchemaEditionValidation = <TNextShape extends ObjectShape>(
  id: string,
  existingShape: TNextShape,
  exclusions?: string[],
): BaseSchema => {
  return useYupSchemaBuilder(id, existingShape, false, exclusions);
};

export default useEntitySettings;
