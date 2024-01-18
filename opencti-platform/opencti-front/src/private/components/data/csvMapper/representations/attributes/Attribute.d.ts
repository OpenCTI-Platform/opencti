import { CsvMapperEditionContainerFragment_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import { DefaultValues } from '../../../../../../utils/defaultValues';

export type CsvMapperRepresentationAttribute = CsvMapperEditionContainerFragment_csvMapper$data['representations'][number]['attributes'][number];

export type CsvMapperRepresentationAttributeEdit = Omit<CsvMapperRepresentationAttribute, 'default_values'> & {
  default_values: string[] | null
};

export interface CsvMapperRepresentationAttributeFormData {
  key: string
  column_name?: string
  separator?: string
  pattern_date?: string
  default_values?: DefaultValues
  based_on?: (string | null)[]
}
