import type { CsvMapperParsed, CsvMapperRepresentation } from "../../../src/modules/internal/csvMapper/csvMapper-types";

export const indicatorsWithExternalReferencesCsvMapper: Partial<CsvMapperParsed> = { // retrieved from debugging console but typing seems not to correspond to CsvMapperParsed
  _index: "opencti_internal_objects-000001",
  id: "f98cecfe-161a-4f4c-80ec-2a5d3abb39a9",
  sort: [
    "csvmapper--1f85cf8c-b19d-5500-9052-b2bb8779d2ec"
  ],
  name: "issue_6287_external_reference",
  has_header: true,
  separator: ",",
  representations: [
    {
      id: "046eb6b3-8e74-4e70-bc95-bb721484fbf2",
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
          key: "externalReferences",
          column: null,
          default_values: null,
          based_on: {
            representations: [
              "7ecba138-7e24-46a3-9ac3-55ec9b8677fb"
            ]
          }
        }
      ]
    },
    {
      id: "7ecba138-7e24-46a3-9ac3-55ec9b8677fb",
      type: "entity",
      target: {
        entity_type: "External-Reference"
      },
      attributes: [
        {
          key: "source_name",
          column: {
            column_name: "C",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "url",
          column: {
            column_name: "C",
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
  internal_id: "f98cecfe-161a-4f4c-80ec-2a5d3abb39a9",
  standard_id: "csvmapper--1f85cf8c-b19d-5500-9052-b2bb8779d2ec",
  creator_id: [
    "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
  ],
  base_type: "ENTITY",
  parent_types: [
    "Basic-Object",
    "Internal-Object"
  ],
  user_chosen_markings: [
    "446c6e54-0f9b-442e-abe9-81508bd54b4a"
  ]
};
export const indicatorsWithExternalReferencesCsvContent = `pattern,main_obs_type,reference
[ipv4-addr:value = '198.168.8.1'],IPv4-Addr,http://twitter.com/filigraner
[ipv4-addr:value = '198.168.8.2'],IPv4-Addr,http://twitter.com/filigraner`;
