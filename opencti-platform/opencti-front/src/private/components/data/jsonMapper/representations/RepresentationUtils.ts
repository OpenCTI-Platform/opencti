import { v4 as uuid } from 'uuid';
import { JsonMapperRepresentationType } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import { JsonMapperRepresentation, JsonMapperRepresentationEdit, JsonMapperRepresentationFormData } from '@components/data/jsonMapper/representations/Representation';
import { formDataToJsonMapperAttribute, jsonMapperAttributeToFormData } from '@components/data/jsonMapper/representations/attributes/AttributeUtils';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from '@components/data/jsonMapper/representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { isEmptyField } from '../../../../../utils/utils';
import { useComputeDefaultValues } from '../../../../../utils/hooks/useDefaultValues';

// -- INIT --

export const representationInitialization = (
  type: JsonMapperRepresentationType,
): JsonMapperRepresentationFormData => {
  return {
    id: uuid(),
    type,
    attributes: {},
    target_type: '',
  };
};

// -- GETTER --

export const representationLabel = (
  idx: number,
  representation: JsonMapperRepresentationFormData,
  t: (message: string) => string,
) => {
  const number = `#${idx + 1}`; // 0-based internally, 1-based for display
  if (isEmptyField(representation.target_type)) {
    return `${number} ${t(`New ${representation.type} representation`)}`;
  }
  const prefix = representation.type === 'entity' ? 'entity_' : 'relationship_';
  const label = `${t(`${prefix}${representation.target_type}`)}`;
  return `${number} ${label[0].toUpperCase()}${label.slice(1)}`;
};

// -- MAPPER --

/**
 * Transform raw json mapper representation data into formik format.
 * @param representation The raw data from backend.
 * @param schemaAttributes All schemas attributes (used to compute default values).
 * @param computeDefaultValues Function to compute default values.
 *
 * @returns Data in formik format.
 */
export const jsonMapperRepresentationToFormData = (
  representation: JsonMapperRepresentation,
  schemaAttributes: JsonMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'],
  computeDefaultValues: ReturnType<typeof useComputeDefaultValues>,
): JsonMapperRepresentationFormData => {
  const entitySchemaAttributes = schemaAttributes.find(
    (schema) => schema.name === representation.target.entity_type,
  )?.attributes ?? [];
  return {
    id: representation.id,
    type: representation.type,
    target_type: representation.target.entity_type,
    column_based: representation.target.column_based?.column_reference ? {
      enabled: true,
      column_reference: representation.target.column_based.column_reference,
      operator: representation.target.column_based.operator,
      value: representation.target.column_based.value,
    } : undefined,
    attributes: representation.attributes.reduce((acc, attribute) => {
      const schemaAttribute = entitySchemaAttributes.find((attr) => attr.name === attribute.key);
      return {
        ...acc,
        [attribute.key]: jsonMapperAttributeToFormData(
          attribute,
          representation.target.entity_type,
          computeDefaultValues,
          schemaAttribute,
        ),
      };
    }, {}),
  };
};

/**
 * Transform mapper representation in formik format to backend format.
 * @param data The formik data.
 *
 * @returns Data in backend format.
 */
export const formDataToJsonMapperRepresentation = (
  data: JsonMapperRepresentationFormData,
): JsonMapperRepresentationEdit => {
  return {
    id: data.id,
    type: data.type as JsonMapperRepresentationType,
    target: {
      entity_type: data.target_type ?? '',
      column_based: data.column_based?.enabled ? {
        column_reference: data.column_based.column_reference,
        operator: data.column_based.operator,
        value: data.column_based.value,
      } : null,
    },
    attributes: (Object.entries(data.attributes)).flatMap(([name, attribute]) => {
      const mapperAttribute = formDataToJsonMapperAttribute(attribute, name);
      return (
        isEmptyField(mapperAttribute.column)
        && isEmptyField(mapperAttribute.based_on)
        && isEmptyField(mapperAttribute.default_values)
      )
        ? []
        : mapperAttribute;
    }),
  };
};
