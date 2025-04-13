import { JsonMapperEditionContainerFragment_jsonMapper$data } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import { DefaultValues } from '../../../../../../utils/defaultValues';

type Mutable<T> = { -readonly [P in keyof T]: T[P]; };
export type JsonMapperRepresentationAttribute = Mutable<JsonMapperEditionContainerFragment_jsonMapper$data['representations'][number]['attributes'][number]>;

export type JsonMapperRepresentationAttributeEdit = Omit<JsonMapperRepresentationAttribute, 'default_values'> & {
  default_values: string[] | null
};

export interface JsonMapperRepresentationAttributeFormData {
  key: string
  mode: string // 'simple' | ' complex' | 'base'
  attr_path?: {
    path: string
    independent: boolean | undefined | null
    configuration: {
      pattern_date: string | null | undefined;
      separator: string | null | undefined;
      timezone: string | null | undefined;
    } | null | undefined
  } | null
  complex_path?: {
    formula: string
  }
  based_on?: {
    identifier?: string[] | undefined | null
    representations?: string[] | undefined | null
  } | null
  default_values?: DefaultValues
}
