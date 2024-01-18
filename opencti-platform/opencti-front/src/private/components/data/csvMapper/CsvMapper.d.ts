import { CsvMapperRepresentationEdit, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import { CsvMapperEditionContainerFragment_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';

export type CsvMapperEdit = Omit<CsvMapperEditionContainerFragment_csvMapper$data, ' $fragmentType' | 'errors' | 'representations'> & {
  representations: CsvMapperRepresentationEdit[]
};

export interface CsvMapperFormData {
  id: string
  separator: string
  has_header: boolean
  name?: string
  skip_line_char?: string
  entity_representations: CsvMapperRepresentationFormData[]
  relationship_representations: CsvMapperRepresentationFormData[]
  errors?: string
}
