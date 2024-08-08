import { graphql, useLazyLoadQuery, useFragment, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import { ObjectSchema, ObjectShape, Schema } from 'yup';
import {
  EntitySettingSettings_entitySetting$data,
  EntitySettingSettings_entitySetting$key,
} from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingSettings_entitySetting.graphql';
import { useSchemaAttributesQuery } from './__generated__/useSchemaAttributesQuery.graphql';
import { useFormatter } from '../../components/i18n';
import useAuth from './useAuth';
import { entitySettingFragment } from '../../private/components/settings/sub_types/entity_setting/EntitySettingSettings';

export const SchemaAttributesQuery = graphql`
  query useSchemaAttributesQuery($entityType: String!) {
    schemaAttributes(entityType: $entityType) {
      name
      mandatory
      multiple
      label
      type
    }
  }
`;
export type EntitySetting = EntitySettingSettings_entitySetting$data;

const useEntitySettings = (entityType?: string | string[]): EntitySetting[] => {
  const { entitySettings } = useAuth();
  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];
  return entitySettings.edges
    .map(({ node }) => useFragment<EntitySettingSettings_entitySetting$key>(entitySettingFragment, node))
    .filter(({ target_type }: EntitySetting) => (entityType ? entityTypes.includes(target_type) : true));
};

export const useDynamicIsEnforceReference = (id: string): boolean => {
  return useEntitySettings(id).some(
    (node) => node.enforce_reference !== null && node.enforce_reference,
  );
};

type QueryReferenceType = PreloadedQuery<useSchemaAttributesQuery, Record<string | number | symbol, unknown>>;

/**
 * Given a preloaded query reference, fetches schema attributes and filters down
 * to only the mandatory attributes.
 *
 * @param queryReference Preloaded query reference
 * @returns String list of mandatory attributes
 */
export const getMandatoryTypes = (queryReference: QueryReferenceType) => {
  const data = usePreloadedQuery<useSchemaAttributesQuery>(
    SchemaAttributesQuery,
    queryReference,
  );
  if (data) {
    const mandatoryAttributes = data.schemaAttributes.filter((item) => item.mandatory).map((ele) => ele.name);
    return mandatoryAttributes;
  }
  return [];
};

/**
 * Builds a Yup Schema where each key is conditionally required. If a key is in
 * the provided mandatoryTypes, it is required in the resulting schema.
 *
 * @param shape Original Yup Schema
 * @param mandatoryTypes List of keys that are required in the final schema
 * @returns Final Yup Schema with required fields
 */
export const yupShapeConditionalRequired = (shape: Record<string, Yup.Schema>, mandatoryTypes: string[]) => {
  const { t_i18n } = useFormatter();
  return Object.entries(shape).reduce((result, [key, value]) => {
    return mandatoryTypes.includes(key)
      ? { ...result, [key]: value.required(t_i18n('This field is required')) }
      : { ...result, [key]: value };
  }, {});
};

export const useDynamicMandatorySchemaAttributes = (
  entityType: string,
):string[] => {
  const data = useLazyLoadQuery<useSchemaAttributesQuery>(
    SchemaAttributesQuery,
    { entityType },
    {
      fetchPolicy: 'store-and-network',
    },
  );
  const mandatoryAttributes = data.schemaAttributes.filter((item) => item.mandatory).map((ele) => ele.name);
  return mandatoryAttributes;
};

export const useYupDynamicSchemaBuilder = (
  entityType: string,
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
  const mandatoryAttributes = useDynamicMandatorySchemaAttributes(entityType);
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
  entityType: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupDynamicSchemaBuilder(entityType, existingShape, true, exclusions);
};

export const useDynamicSchemaEditionValidation = (
  entityType: string,
  existingShape: ObjectShape,
  exclusions?: string[],
): ObjectSchema<{ [p: string]: unknown }> => {
  return useYupDynamicSchemaBuilder(entityType, existingShape, false, exclusions);
};
