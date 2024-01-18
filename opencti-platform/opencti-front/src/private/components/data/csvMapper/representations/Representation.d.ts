import { CsvMapperRepresentationAttributeEdit, CsvMapperRepresentationAttributeFormData } from '@components/data/csvMapper/representations/attributes/Attribute';
import { CsvMapperEditionContainerFragment_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';

export type CsvMapperRepresentation = CsvMapperEditionContainerFragment_csvMapper$data['representations'][number];

export type CsvMapperRepresentationEdit = Omit<CsvMapperRepresentation, 'attributes'> & {
  attributes: CsvMapperRepresentationAttributeEdit[]
};

export interface CsvMapperRepresentationFormData {
  id: string
  type: string
  target_type?: string
  attributes: {
    [key: string]: CsvMapperRepresentationAttributeFormData
  }
}
