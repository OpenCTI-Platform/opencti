import type { CsvMapperParsed, CsvMapperRepresentation } from '../../../src/modules/internal/csvMapper/csvMapper-types';

export const indicatorsWithLabelsCsvMapper: Partial<CsvMapperParsed> = {
  _index: "opencti_internal_objects-000001",
  id: "dea4a6b4-cb44-4070-86fd-f807b7146b3a",
  sort: [
    "csvmapper--87f1d7cc-0d7a-577e-aa7f-310cd159fba6"
  ],
  name: "7036_labels",
  has_header: true,
  separator: ",",
  representations: [
    {
      id: "a31c7685-75dc-4f8d-916b-1d6f6f97ace3",
      type: "entity",
      target: {
        entity_type: "Indicator"
      },
      attributes: [
        {
          key: "name",
          column: {
            column_name: "A",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "pattern_type",
          column: null,
          default_values: [
            "stix"
          ],
          based_on: null
        },
        {
          key: "pattern",
          column: {
            column_name: "A",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "x_opencti_main_observable_type",
          column: null,
          default_values: [
            "IPv4-Addr"
          ],
          based_on: null
        },
        {
          key: "objectLabel",
          column: null,
          default_values: null,
          based_on: {
            representations: [
              "1b38e169-7f87-4f32-97a4-35cc0339d56f"
            ]
          }
        }
      ]
    },
    {
      id: "1b38e169-7f87-4f32-97a4-35cc0339d56f",
      type: "entity",
      target: {
        entity_type: "Label"
      },
      attributes: [
        {
          key: "value",
          column: {
            column_name: "C",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "color",
          column: {
            column_name: "D",
            configuration: null
          },
          default_values: null,
          based_on: null
        }
      ]
    }
  ] as unknown as CsvMapperRepresentation[],
  skipLineChar: "",
  confidence: 100,
  entity_type: "CsvMapper",
  internal_id: "dea4a6b4-cb44-4070-86fd-f807b7146b3a",
  standard_id: "csvmapper--87f1d7cc-0d7a-577e-aa7f-310cd159fba6",
  creator_id: [
    "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
  ],
  base_type: "ENTITY",
  parent_types: [
    "Basic-Object",
    "Internal-Object"
  ]
}

export const indicatorsWithLabelsCsvContent = `pattern,main_obs_type,label,color
[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3
[ipv4-addr:value = '198.168.8.6'],IPv4-Addr,filigran,0b41f3`;
