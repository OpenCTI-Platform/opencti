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
  type: string // entity / relationship
  identifier?: string | null
  target?: {
    entity_type?: string
    path?: string
  }
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
