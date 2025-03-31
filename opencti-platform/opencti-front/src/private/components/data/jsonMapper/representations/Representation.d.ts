import { JsonMapperRepresentationAttributeEdit, JsonMapperRepresentationAttributeFormData } from '@components/data/jsonMapper/representations/attributes/Attribute';
import {
  JsonMapperEditionContainerFragment_jsonMapper$data,
  JsonMapperOperator,
} from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';

export type JsonMapperRepresentation = JsonMapperEditionContainerFragment_jsonMapper$data['representations'][number];

export type JsonMapperRepresentationEdit = Omit<JsonMapperRepresentation, 'attributes'> & {
  attributes: JsonMapperRepresentationAttributeEdit[]
};

export interface JsonMapperRepresentationFormData {
  id: string
  type: string
  target_type?: string
  column_based?: JsonMapperColumnBasedFormData | null
  attributes: {
    [key: string]: JsonMapperRepresentationAttributeFormData
  }
}

export interface JsonMapperColumnBasedFormData {
  enabled: boolean
  column_reference?: string | null
  operator?: JsonMapperOperator | null
  value?: string | null
}
