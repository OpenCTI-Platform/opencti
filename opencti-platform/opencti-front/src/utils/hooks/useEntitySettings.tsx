import { useFragment } from 'react-relay';
import * as Yup from 'yup';
import { ObjectSchema, ObjectShape, Schema } from 'yup';
import {
  EntitySettingSettings_entitySetting$data,
  EntitySettingSettings_entitySetting$key,
} from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingSettings_entitySetting.graphql';
import { entitySettingFragment } from '../../private/components/settings/sub_types/entity_setting/EntitySettingSettings';
import useAuth from './useAuth';
import { useFormatter } from '../../components/i18n';

export type EntitySetting = EntitySettingSettings_entitySetting$data;

const useEntitySettings = (entityType?: string | string[]): EntitySetting[] => {
  const { entitySettings } = useAuth();
  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];
  return entitySettings.edges
    .map(({ node }) => useFragment<EntitySettingSettings_entitySetting$key>(entitySettingFragment, node))
    .filter(({ target_type }: EntitySetting) => (entityType ? entityTypes.includes(target_type) : true));
};

export const useHiddenEntities = () => {
  const { me } = useAuth();
  const platformHiddenTypes = useEntitySettings().filter((n) => n.platform_hidden_type === true).map((n) => n.target_type);
  return [...platformHiddenTypes, ...me.default_hidden_types];
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

export const useIsMandatoryAttribute = (id: string) => {
  const entitySettings = useEntitySettings(id).at(0);
  if (!entitySettings) {
    throw Error(`Invalid type for setting: ${id}`);
  }
  const mandatoryAttributes = [...entitySettings.mandatoryAttributes];
  // In creation, if enforce_reference is activated, externalReferences is required
  if (entitySettings.enforce_reference === true) {
    mandatoryAttributes.push('externalReferences');
  }
  return { entitySettings, mandatoryAttributes };
};

export const useYupSchemaBuilder = (
  id: string,
  existingShape: ObjectShape,
  isCreation: boolean,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  // simplest case: we're in update mode, so we do not need all mandatory fields
  if (!isCreation) {
    return Yup.object().shape(existingShape);
  }

  // we're in creation mode, let's find if all mandatory fields are set
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(id);
  const existingKeys = Object.keys(existingShape);

  const newShape: ObjectShape = Object.fromEntries(
    mandatoryAttributes
      .filter((attr) => !(exclusions ?? []).includes(attr))
      .map((attrName: string) => {
        let validator: Schema;

        if (existingKeys.includes(attrName)) {
          if ((existingShape[attrName] as Schema).type === 'date') {
            // DateTimePickerField will default an empty date to 'null'
            // Yup has issues with validating 'null' dates as required, so we will swap it
            // to 'undefined' to get the validator to identify the missing required field
            validator = (existingShape[attrName] as Schema)
              .transform((v) => ((v === null) ? undefined : v))
              .required(t_i18n('This field is required'))
              .nullable(false);
          } else {
            validator = (existingShape[attrName] as Schema)
              .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
              .required(t_i18n('This field is required'))
              .nullable(false);
          }
        } else {
          validator = Yup.mixed()
            .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t_i18n('This field is required'));
        }
        return [attrName, validator];
      }),
  );
  return Yup.object().shape({ ...existingShape, ...newShape });
};

export const useSchemaCreationValidation = (
  id: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupSchemaBuilder(id, existingShape, true, exclusions);
};

export const useSchemaEditionValidation = (
  id: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupSchemaBuilder(id, existingShape, false, exclusions);
};

/**
 * Builds a Yup Schema where each key is conditionally required. If a key is in
 * the provided mandatoryTypes, it is required in the resulting schema.
 *
 * @param shape Original Yup Schema
 * @param mandatoryTypes List of keys that are required in the final schema
 * @returns Final Yup Schema with required fields
 */
export const yupShapeConditionalRequired = (
  shape: Record<string, Yup.Schema>,
  mandatoryTypes: string[],
): Record<string, Yup.Schema> => {
  const { t_i18n } = useFormatter();
  const requiredMsg = t_i18n('This field is required');

  return Object.entries(shape).reduce((result, [key, value]) => {
    let updatedValue = value;

    if (mandatoryTypes.includes(key)) {
      if (value.type === 'array') {
        // If the value is an array, ensure it's not empty and not null
        updatedValue = Yup.array().min(1, requiredMsg);
      } else {
        updatedValue = value.required(requiredMsg);
      }
    }

    return { ...result, [key]: updatedValue };
  }, {});
};

const useYupDynamicSchemaBuilder = (
  mandatoryAttributes: string[],
  existingShape: ObjectShape,
  isCreation: boolean,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  // simplest case: we're in update mode, so we do not need all mandatory fields
  if (!isCreation) {
    return Yup.object().shape(existingShape);
  }
  // we're in creation mode, let's find if all mandatory fields are set
  const { t_i18n } = useFormatter();
  const existingKeys = Object.keys(existingShape);
  const newShape: ObjectShape = Object.fromEntries(
    mandatoryAttributes
      .filter((attr) => !(exclusions ?? []).includes(attr))
      .map((attrName: string) => {
        let validator: Schema;
        if (existingKeys.includes(attrName)) {
          if ((existingShape[attrName] as Schema).type === 'date') {
            // DateTimePickerField will default an empty date to 'null'
            // Yup has issues with validating 'null' dates as required, so we will swap it
            // to 'undefined' to get the validator to identify the missing required field
            validator = (existingShape[attrName] as Schema)
              .transform((v) => ((v === null) ? undefined : v))
              .required(t_i18n('This field is required'))
              .nullable(false);
          } else {
            validator = (existingShape[attrName] as Schema)
              .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
              .required(t_i18n('This field is required'))
              .nullable(false);
          }
        } else {
          validator = Yup.mixed()
            .transform((v) => ((Array.isArray(v) && v.length === 0) ? undefined : v))
            .required(t_i18n('This field is required'));
        }
        return [attrName, validator];
      }),
  );

  return Yup.object().shape({ ...existingShape, ...newShape });
};

export const useDynamicSchemaCreationValidation = (
  mandatoryAttributes: string[],
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupDynamicSchemaBuilder(
    mandatoryAttributes,
    existingShape,
    true,
    exclusions,
  );
};

export const useDynamicSchemaEditionValidation = (
  mandatoryAttributes: string[],
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupDynamicSchemaBuilder(
    mandatoryAttributes,
    existingShape,
    false,
    exclusions,
  );
};

export default useEntitySettings;
