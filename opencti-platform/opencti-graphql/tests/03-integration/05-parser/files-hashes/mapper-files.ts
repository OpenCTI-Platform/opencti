import { type CsvMapperParsed } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { repFile } from './representation-file';

export const csvMapperFile: Partial<CsvMapperParsed> = {
  id: 'mapper-file',
  has_header: true,
  separator: ',',
  representations: [
    repFile
  ]
};
