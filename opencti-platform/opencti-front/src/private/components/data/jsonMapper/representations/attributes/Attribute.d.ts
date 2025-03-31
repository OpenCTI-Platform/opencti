import { JsonMapperEditionContainerFragment_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import { DefaultValues } from '../../../../../../utils/defaultValues';

export type JsonMapperRepresentationAttribute = JsonMapperEditionContainerFragment_jsonMapper$data['representations'][number]['attributes'][number];

export type JsonMapperRepresentationAttributeEdit = Omit<JsonMapperRepresentationAttribute, 'default_values'> & {
  default_values: string[] | null
};

export interface JsonMapperRepresentationAttributeFormData {
  key: string
  column_name?: string
  separator?: string
  pattern_date?: string
  default_values?: DefaultValues
  based_on?: (string | null | undefined)[]
}
