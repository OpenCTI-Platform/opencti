import { type BasicStoreEntityCsvMapper, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';

export const csvMapperMalware: Partial<BasicStoreEntityCsvMapper> = {
  id: 'mapper-malware',
  has_header: true,
  separator: ',',
  representations: [
    {
      id: 'representation01',
      type: CsvMapperRepresentationType.entity,
      target: {
        entity_type: ENTITY_TYPE_MALWARE,
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
        {
          key: 'is_family',
          column: {
            column_name: 'B',
          },
        },
      ]
    }
  ]
};
