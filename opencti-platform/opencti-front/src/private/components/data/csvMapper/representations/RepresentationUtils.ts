import { v4 as uuid } from 'uuid';
import { CsvMapperRepresentationType } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import { CsvMapperRepresentation, CsvMapperRepresentationEdit, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import { csvMapperAttributeToFormData, formDataToCsvMapperAttribute } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { isEmptyField } from '../../../../../utils/utils';
import { useComputeDefaultValues } from '../../../../../utils/hooks/useDefaultValues';

// -- INIT --

export const representationInitialization = (
  type: CsvMapperRepresentationType,
): CsvMapperRepresentationFormData => {
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
  representation: CsvMapperRepresentationFormData,
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
 * Transform raw csv mapper representation data into formik format.
 * @param representation The raw data from backend.
 * @param schemaAttributes All schemas attributes (used to compute default values).
 * @param computeDefaultValues Function to compute default values.
 *
 * @returns Data in formik format.
 */
export const csvMapperRepresentationToFormData = (
  representation: CsvMapperRepresentation,
  schemaAttributes: CsvMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'],
  computeDefaultValues: ReturnType<typeof useComputeDefaultValues>,
): CsvMapperRepresentationFormData => {
  const entitySchemaAttributes = schemaAttributes.find(
    (schema) => schema.name === representation.target.entity_type,
  )?.attributes ?? [];

  return {
    id: representation.id,
    type: representation.type,
    target_type: representation.target.entity_type,
    attributes: representation.attributes.reduce((acc, attribute) => {
      const schemaAttribute = entitySchemaAttributes.find((attr) => attr.name === attribute.key);
      return {
        ...acc,
        [attribute.key]: csvMapperAttributeToFormData(
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
export const formDataToCsvMapperRepresentation = (
  data: CsvMapperRepresentationFormData,
): CsvMapperRepresentationEdit => {
  return {
    id: data.id,
    type: data.type as CsvMapperRepresentationType,
    target: {
      entity_type: data.target_type ?? '',
    },
    attributes: (Object.entries(data.attributes)).flatMap(([name, attribute]) => {
      const mapperAttribute = formDataToCsvMapperAttribute(attribute, name);
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
