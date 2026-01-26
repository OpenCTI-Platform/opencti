import { type CsvMapperParsed, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_DOMAIN_NAME, ENTITY_EMAIL_ADDR, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL } from '../../../../src/schema/stixCyberObservable';
import { CsvMapperOperator } from '../../../../src/generated/graphql';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';

export const csvMapperDynamicChar: Partial<CsvMapperParsed> = {
  id: 'dyn-mapper-char',
  has_header: true,
  separator: ';',
  representations: [
    {
      id: 'representationIP',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_IPV4_ADDR,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'IPv4-Addr '
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
          operator: CsvMapperOperator.Eq,
          value: 'Url '
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
      id: 'representationEmail',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_EMAIL_ADDR,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'Mèl'
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
      id: 'representationIpv6',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_IPV6_ADDR,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'IP/6'
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
      id: 'representationDomain',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_DOMAIN_NAME,
        column_based: {
          column_reference: 'E',
          operator: CsvMapperOperator.Eq,
          value: 'Domain Name'
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
    },
    {
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
