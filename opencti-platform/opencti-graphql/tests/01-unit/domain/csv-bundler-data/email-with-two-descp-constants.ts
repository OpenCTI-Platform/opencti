import { type CsvMapperParsed, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_EMAIL_ADDR } from '../../../../src/schema/stixCyberObservable';

export const emailWithTwoDescCsvMapper: Partial<CsvMapperParsed> = {
  id: 'mapper-mock-email-and-desc',
  has_header: false,
  separator: ',',
  entity_type: 'CsvMapper',
  name: 'EmailCsvMapper',
  representations: [
    {
      id: 'emailRepresentation',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_EMAIL_ADDR,
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'A',
          },
        },
        {
          key: 'x_opencti_description',
          column: {
            column_name: 'B',
          },
        }
      ]
    }
  ]
};
