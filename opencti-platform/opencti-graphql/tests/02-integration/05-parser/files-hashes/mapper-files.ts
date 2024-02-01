import { type BasicStoreEntityCsvMapper } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { repFile } from './representation-file';

export const csvMapperFile: Partial<BasicStoreEntityCsvMapper> = {
  id: 'mapper-file',
  has_header: true,
  separator: ',',
  representations: [
    repFile
  ]
};
