import type { CsvMapperParsed, CsvMapperRepresentation } from "../../../src/modules/internal/csvMapper/csvMapper-types";

export const indicatorsWithKillChainPhasesCsvMapper: Partial<CsvMapperParsed> = {
  _index: "opencti_internal_objects-000001",
  id: "4dbb5c36-a8e4-4666-a7ed-6d520ea7e483",
  sort: [
    "csvmapper--e54d2dce-9387-5249-a337-0452576316bb"
  ],
  name: "7036_kill_chains",
  has_header: true,
  separator: ",",
  representations: [
    {
      id: "bf2cca02-30da-4e8e-b9cb-94f7cd74dd3d",
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
          key: "killChainPhases",
          column: null,
          default_values: null,
          based_on: {
            representations: [
              "9b0e11bb-032f-400c-8db3-ccb6f700cde5"
            ]
          }
        }
      ]
    },
    {
      id: "9b0e11bb-032f-400c-8db3-ccb6f700cde5",
      type: "entity",
      target: {
        entity_type: "Kill-Chain-Phase"
      },
      attributes: [
        {
          key: "kill_chain_name",
          column: {
            column_name: "C",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "phase_name",
          column: {
            column_name: "D",
            configuration: null
          },
          default_values: null,
          based_on: null
        },
        {
          key: "x_opencti_order",
          column: {
            column_name: "E",
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
  internal_id: "4dbb5c36-a8e4-4666-a7ed-6d520ea7e483",
  standard_id: "csvmapper--e54d2dce-9387-5249-a337-0452576316bb",
  creator_id: [
    "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
  ],
  base_type: "ENTITY",
  parent_types: [
    "Basic-Object",
    "Internal-Object"
  ],
}

export const indicatorsWithKillChainPhasesCsvContent = `pattern,main_obs_type,kill_chain_name,kill_chain_phase_name,order
[ipv4-addr:value = '198.168.8.3'],IPv4-Addr,kill_chain_name_1,kill_chain_phase_name_1,1
[ipv4-addr:value = '198.168.8.4'],IPv4-Addr,kill_chain_name_1,kill_chain_phase_name_1,1`;