import { JsonMapperEdit, JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import { formDataToJsonMapperRepresentation, jsonMapperRepresentationToFormData } from '@components/data/jsonMapper/representations/RepresentationUtils';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from '@components/data/jsonMapper/representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';
import { JsonMapperEditionContainerFragment_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import { isNotEmptyField } from '../../../../utils/utils';
import { useComputeDefaultValues } from '../../../../utils/hooks/useDefaultValues';

type JsonMapperRepresentations = JsonMapperEditionContainerFragment_jsonMapper$data['representations'];

type JsonMapperAddInput = {
  id: string,
  name: string,
  errors: string | null | undefined,
  representations: JsonMapperRepresentations,
};

/**
 * Transform raw json mapper data into formik format.
 * @param jsonMapper The raw data from backend.
 * @param schemaAttributes All schemas attributes (used to compute default values).
 * @param computeDefaultValues Function to compute default values.
 *
 * @returns Data in formik format.
 */
export const jsonMapperToFormData = (
  jsonMapper: JsonMapperAddInput,
  schemaAttributes: JsonMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'],
  computeDefaultValues: ReturnType<typeof useComputeDefaultValues>,
): JsonMapperFormData => {
  return {
    id: jsonMapper.id,
    name: jsonMapper.name,
    entity_representations: jsonMapper.representations.flatMap((rep) => {
      if (rep.type !== 'entity') return [];
      return jsonMapperRepresentationToFormData(rep, schemaAttributes, computeDefaultValues);
    }),
    relationship_representations: jsonMapper.representations.flatMap((rep) => {
      if (rep.type !== 'relationship') return [];
      return jsonMapperRepresentationToFormData(rep, schemaAttributes, computeDefaultValues);
    }),
    errors: jsonMapper.errors ?? undefined,
  };
};

/**
 * Transform mapper in formik format to backend format.
 * @param data The formik data.
 *
 * @returns Data in backend format.
 */
export const formDataToJsonMapper = (
  data: JsonMapperFormData,
): JsonMapperEdit => {
  return {
    id: data.id,
    name: data.name ?? '',
    representations: [
      ...data.entity_representations.map(formDataToJsonMapperRepresentation),
      ...data.relationship_representations.map(formDataToJsonMapperRepresentation),
    ].filter((r) => isNotEmptyField(r.target.entity_type)),
  };
};
