import type { CsvMapperParsed, CsvMapperRepresentation } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import type { StixBundle, StixDomainObject } from '../../../src/types/stix-common';

export const indicatorsWithLabelsExpectedBundle: StixBundle = {
  id: 'bundle--c8593959-d4b1-4ccf-95d5-bee644cf2c9b',
  spec_version: '2.1',
  type: 'bundle',
  objects: [
    {
      color: '0b41f3',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          converter_csv: "[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3",
          extension_type: 'new-sdo',
          type: 'Label',
        },
      },
      id: 'label--a70c2bda-5811-5dee-bd73-c19aa48f15df',
      spec_version: '2.1',
      type: 'label',
      value: 'filigran',
    },
    {
      extensions: {
        'extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b': {
          extension_type: 'property-extension',
        },
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          converter_csv: "[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3",
          extension_type: 'property-extension',
          labels_ids: [
            undefined,
          ],
          main_observable_type: 'IPv4-Addr',
          observable_values: [
            {
              type: 'IPv4-Addr',
              value: '198.168.8.5',
            },
          ],
          type: 'Indicator',
        },
      },
      id: 'indicator--c23d17a1-d085-51a3-8774-84627a986061',
      spec_version: '2.1',
      pattern_type: 'stix',
      pattern: "[ipv4-addr:value = '198.168.8.5']",
      name: "[ipv4-addr:value = '198.168.8.5']",
      labels: [
        'filigran'
      ],
      type: 'indicator'
    },
    {
      extensions: {
        'extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b': {
          extension_type: 'property-extension',
        },
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          converter_csv: "[ipv4-addr:value = '198.168.8.6'],IPv4-Addr,filigran,0b41f3",
          extension_type: 'property-extension',
          labels_ids: [
            undefined,
          ],
          main_observable_type: 'IPv4-Addr',
          observable_values: [
            {
              type: 'IPv4-Addr',
              value: '198.168.8.6',
            },
          ],
          type: 'Indicator',
        },
      },
      id: 'indicator--62a69445-3d8e-5ade-9f75-986ab8ce5494',
      spec_version: '2.1',
      pattern_type: 'stix',
      pattern: "[ipv4-addr:value = '198.168.8.6']",
      name: "[ipv4-addr:value = '198.168.8.6']",
      labels: [
        'filigran'
      ],
      type: 'indicator'
    }
  ] as unknown as StixDomainObject[]
};

export const indicatorsWithLabelsCsvMapper: Partial<CsvMapperParsed> = {
  _index: 'opencti_internal_objects-000001',
  id: 'dea4a6b4-cb44-4070-86fd-f807b7146b3a',
  sort: [
    'csvmapper--87f1d7cc-0d7a-577e-aa7f-310cd159fba6'
  ],
  name: '7036_labels',
  has_header: true,
  separator: ',',
  representations: [
    {
      id: 'a31c7685-75dc-4f8d-916b-1d6f6f97ace3',
      type: 'entity',
      target: {
        entity_type: 'Indicator'
      },
      attributes: [
        {
          key: 'name',
          column: {
            column_name: 'A',
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: 'pattern_type',
          column: null,
          default_values: [
            'stix'
          ],
          based_on: null
        },
        {
          key: 'pattern',
          column: {
            column_name: 'A',
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: 'x_opencti_main_observable_type',
          column: null,
          default_values: [
            'IPv4-Addr'
          ],
          based_on: null
        },
        {
          key: 'objectLabel',
          column: null,
          default_values: null,
          based_on: {
            representations: [
              '1b38e169-7f87-4f32-97a4-35cc0339d56f'
            ]
          }
        }
      ]
    },
    {
      id: '1b38e169-7f87-4f32-97a4-35cc0339d56f',
      type: 'entity',
      target: {
        entity_type: 'Label'
      },
      attributes: [
        {
          key: 'value',
          column: {
            column_name: 'C',
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: 'color',
          column: {
            column_name: 'D',
            configuration: null
          },
          default_values: null,
          based_on: null
        }
      ]
    }
  ] as unknown as CsvMapperRepresentation[],
  skipLineChar: '',
  confidence: 100,
  entity_type: 'CsvMapper',
  internal_id: 'dea4a6b4-cb44-4070-86fd-f807b7146b3a',
  standard_id: 'csvmapper--87f1d7cc-0d7a-577e-aa7f-310cd159fba6',
  creator_id: [
    '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
  ],
  base_type: 'ENTITY',
  parent_types: [
    'Basic-Object',
    'Internal-Object'
  ]
};

export const indicatorsWithLabelsCsvContent = `pattern,main_obs_type,label,color
[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3
[ipv4-addr:value = '198.168.8.6'],IPv4-Addr,filigran,0b41f3`;
