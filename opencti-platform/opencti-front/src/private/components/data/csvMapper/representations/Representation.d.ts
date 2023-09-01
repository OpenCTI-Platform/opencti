import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import {
  CsvMapperRepresentationType,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';

export interface Representation {
  id: string;
  target: {
    entity_type: string;
  };
  type: CsvMapperRepresentationType;
  attributes: Attribute[];
}
