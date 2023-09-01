import { Representation } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperEditionContainerFragment_csvMapper$data,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';

export interface CsvMapper extends Omit<CsvMapperEditionContainerFragment_csvMapper$data, ' $fragmentType'> {
  id?: string;
  representations: Representation[],
}
