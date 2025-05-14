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
    target: {
      entity_type: '',
      path: '',
    },
  };
};

// -- GETTER --

export const representationLabel = (
  idx: number,
  representation: JsonMapperRepresentationFormData,
  t: (message: string) => string,
) => {
  const number = `#${idx + 1}`; // 0-based internally, 1-based for display
  if (isEmptyField(representation.target?.entity_type)) {
    return `${number} ${t(`New ${representation.type} representation`)}`;
  }
  const prefix = representation.type === 'entity' ? 'entity_' : 'relationship_';
  const label = `${t(`${prefix}${representation.target?.entity_type}`)}`;
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
  const computedSchemaAttributes = [];
  const entitySchemaAttributes = schemaAttributes.find(
    (schema) => schema.name === representation.target.entity_type,
  )?.attributes ?? [];
  for (let i = 0; i < entitySchemaAttributes.length; i += 1) {
    const entitySchemaAttribute = entitySchemaAttributes[i];
    if (entitySchemaAttribute.name === 'hashes') {
      const innerMappings = entitySchemaAttribute.mappings ?? [];
      for (let indexMapping = 0; indexMapping < innerMappings.length; indexMapping += 1) {
        const innerMapping = innerMappings[indexMapping];
        computedSchemaAttributes.push(innerMapping);
      }
    } else {
      computedSchemaAttributes.push(entitySchemaAttribute);
    }
  }
  return {
    attributes: computedSchemaAttributes.reduce((acc, schemaAttribute) => {
      const attribute = representation.attributes.find((attr) => attr.key === schemaAttribute.name);
      if (attribute) {
        return {
          ...acc,
          [attribute.key]: jsonMapperAttributeToFormData(
            attribute,
            representation.target.entity_type,
            computeDefaultValues,
            schemaAttribute as JsonMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'][number]['attributes'][number],
          ),
        };
      }
      return {
        ...acc,
        [schemaAttribute.name]: {
          key: schemaAttribute.name,
          mode: schemaAttribute.type === 'ref' ? 'base' : 'simple',
        },
      };
    }, {}),
    id: representation.id,
    identifier: representation.identifier,
    target: {
      entity_type: representation.target.entity_type,
      path: representation.target.path,
    },
    type: representation.type,
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
      entity_type: data.target?.entity_type ?? '',
      path: data.target?.path ?? '',
    },
    identifier: data.identifier,
    attributes: (Object.entries(data.attributes)).flatMap(([name, attribute]) => {
      const mapperAttribute = formDataToJsonMapperAttribute(attribute, name);
      return (
        isEmptyField(mapperAttribute.attr_path?.path)
        && isEmptyField(mapperAttribute.complex_path?.formula)
        && isEmptyField(mapperAttribute.based_on?.representations)
        && isEmptyField(mapperAttribute.default_values)
      )
        ? []
        : mapperAttribute;
    }),
  };
};
