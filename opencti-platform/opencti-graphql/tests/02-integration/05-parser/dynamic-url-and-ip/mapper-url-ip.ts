import { type CsvMapperParsed, CsvMapperRepresentationType, Operator } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_IPV4_ADDR, ENTITY_URL } from '../../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';

export const csvMapperDynamicIpAndUrl: Partial<CsvMapperParsed> = {
  id: 'dyn-mapper-url-ip',
  has_header: true,
  separator: ';',
  has_entity_dynamic_mapping: true,
  representations: [
    {
      id: 'representationIP',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_IPV4_ADDR,
        column_based: {
          column_reference: 'E',
          operator: Operator.Eq,
          value: 'IPv4-Addr'
        }
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'P',
          },
        },
        {
          key: 'x_opencti_score',
          column: {
            column_name: 'W',
          },
        }
      ]
    }, {
      id: 'representationUrl',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_URL,
        column_based: {
          column_reference: 'E',
          operator: Operator.Eq,
          value: 'Url'
        }
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'P',
          },
        },
        {
          key: 'x_opencti_score',
          column: {
            column_name: 'W',
          },
        }
      ]
    }, {
      id: 'representationIndividual',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        }
      ]
    }
  ]
};
