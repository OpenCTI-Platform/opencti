import {
  CsvMapperRepresentationAttribute,
  CsvMapperRepresentationAttributeEdit,
  CsvMapperRepresentationAttributeFormData,
} from '@components/data/csvMapper/representations/attributes/Attribute';
import { CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { SchemaAttribute } from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributesForm';
import { isNotEmptyField } from '../../../../../../utils/utils';
import { defaultValuesToStringArray } from '../../../../../../utils/defaultValues';
import { useComputeDefaultValues } from '../../../../../../utils/hooks/useDefaultValues';

export const alphabet = (size = 0) => {
  const fn = () => Array.from(Array(26))
    .map((_, i) => i + 65)
    .map((x) => String.fromCharCode(x));
  const letters: string[] = fn();
  for (let step = 0; step < size; step += 1) {
    const additionalLetters = fn();
    const firstLetter = additionalLetters[step];
    letters.push(...additionalLetters.map((l) => firstLetter.concat(l)));
  }
  return letters;
};

// -- GETTER --

// try to compute a label from the attribute schema
// Cascading attempts if the following fields exist : label, then name
export const getAttributeLabel = (schemaAttribute: SchemaAttribute) => {
  return schemaAttribute.label ?? schemaAttribute.name;
};

// based_on is an array of ids
// this function gives the corresponding array of Representation objects
export const getBasedOnRepresentations = (
  attribute: CsvMapperRepresentationAttributeFormData | undefined,
  representations: CsvMapperRepresentationFormData[],
) => {
  return attribute?.based_on?.flatMap((r) => {
    const rep = representations.find((o) => o.id === r);
    return rep ?? [];
  }) ?? [];
};

// get the entity type of given ref "from" or "to"
// (refs links to an existing representation)
export const getInfoForRef = (
  attributes: CsvMapperRepresentationAttributeFormData[],
  representations: CsvMapperRepresentationFormData[],
  keyRef: 'from' | 'to',
) => {
  const ref = attributes.find((attr) => attr.key === keyRef);
  let fromType: string | undefined;
  if (ref && isNotEmptyField(ref.based_on)) {
    const firstRepresentationId = ref.based_on[0];
    if (firstRepresentationId) {
      fromType = representations.find((r) => r.id === firstRepresentationId)
        ?.target_type;
      return [fromType, firstRepresentationId];
    }
  }
  return [];
};

/**
 * Transform raw csv mapper attribute data into formik format.
 * @param attribute The raw data from backend.
 * @param entityType Entity type of the current representation.
 * @param schemaAttribute Schemas attribute (used to compute default values).
 * @param computeDefaultValues Function to compute default values.
 *
 * @returns Data in formik format.
 */
export const csvMapperAttributeToFormData = (
  attribute: CsvMapperRepresentationAttribute,
  entityType: string,
  computeDefaultValues: ReturnType<typeof useComputeDefaultValues>,
  schemaAttribute?: CsvMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'][number]['attributes'][number],
): CsvMapperRepresentationAttributeFormData => {
  return {
    key: attribute.key,
    column_name: attribute.column?.column_name ?? undefined,
    separator: attribute.column?.configuration?.separator ?? undefined,
    pattern_date: attribute.column?.configuration?.pattern_date ?? undefined,
    default_values: schemaAttribute ? computeDefaultValues(
      entityType,
      attribute.key,
      schemaAttribute.multiple,
      schemaAttribute.type,
      attribute.default_values ?? [],
    ) : null,
    based_on: attribute.based_on?.representations
      ? [...(attribute.based_on?.representations ?? [])]
      : undefined,
  };
};

/**
 * Transform mapper attribute in formik format to backend format.
 * @param data The formik data.
 * @param name Name attribute.
 *
 * @returns Data in backend format.
 */
export const formDataToCsvMapperAttribute = (
  data: CsvMapperRepresentationAttributeFormData,
  name?: string,
): CsvMapperRepresentationAttributeEdit => {
  const based_on = isNotEmptyField(data.based_on)
    ? { representations: data.based_on }
    : null;

  const default_values = isNotEmptyField(data.default_values)
    ? defaultValuesToStringArray(data.default_values ?? null)
    : null;

  const configuration = isNotEmptyField(data.pattern_date)
    || isNotEmptyField(data.separator)
    ? {
      pattern_date: data.pattern_date ?? null,
      separator: data.separator ?? null,
    }
    : null;

  const column = isNotEmptyField(data.column_name) || isNotEmptyField(configuration)
    ? {
      column_name: data.column_name ?? null,
      configuration,
    }
    : null;

  return {
    key: name ?? data.key,
    column,
    default_values,
    based_on,
  };
};
