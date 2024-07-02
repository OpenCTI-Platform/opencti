import { describe, it, expect } from 'vitest';
import { bundleProcess } from '../../../src/parser/csv-bundler';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { StixBundle, StixDomainObject } from '../../../src/types/stix-common';
import {
  indicatorsWithExternalReferencesCsvContent,
  indicatorsWithExternalReferencesCsvMapper
} from '../../data/csv-bundler/external-references-constants';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { indicatorsWithLabelsCsvContent, indicatorsWithLabelsCsvMapper } from '../../data/csv-bundler/labels-constants';
import {
  indicatorsWithKillChainPhasesCsvContent,
  indicatorsWithKillChainPhasesCsvMapper
} from '../../data/csv-bundler/kill-chains-constants';

describe('CSV bundler', () => {
  describe('Embedded properties', () => {
    it('Should list external references', async () => {
      const indicatorsWithExternalReferencesExpectedBundle: StixBundle = {
        id: "bundle--bfb3d6f4-6961-4fd0-8fb6-afbcbf2e0d59",
        spec_version: "2.1",
        type: "bundle",
        objects: [
          {
            id: "indicator--7be2cb5d-ec2b-5bdd-89eb-5802b71faabd",
            spec_version: "2.1",
            type: "indicator",
            extensions: {
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                extension_type: "property-extension",
                type: "Indicator",
                main_observable_type: "IPv4-Addr",
                converter_csv: "[ipv4-addr:value = '198.168.8.1'],IPv4-Addr,http://twitter.com/filigraner"
              },
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension"
              }
            },
            external_references: [
              {
                source_name: "http://twitter.com/filigraner",
                url: "http://twitter.com/filigraner"
              }
            ],
            name: "[ipv4-addr:value = '198.168.8.1']",
            pattern: "[ipv4-addr:value = '198.168.8.1']",
            pattern_type: "stix"
          },
          {
            id: "indicator--adf3f1be-c67d-5f8a-85fb-3668f411d8b8",
            spec_version: "2.1",
            type: "indicator",
            extensions: {
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                extension_type: "property-extension",
                type: "Indicator",
                main_observable_type: "IPv4-Addr",
                converter_csv: "[ipv4-addr:value = '198.168.8.2'],IPv4-Addr,http://twitter.com/filigraner"
              },
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension"
              }
            },
            external_references: [
              {
                source_name: "http://twitter.com/filigraner",
                url: "http://twitter.com/filigraner"
              }
            ],
            name: "[ipv4-addr:value = '198.168.8.2']",
            pattern: "[ipv4-addr:value = '198.168.8.2']",
            pattern_type: "stix"
          }
        ] as unknown as StixDomainObject[]
      }
      const indicatorsWithExternalReferencesActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        Buffer.from(indicatorsWithExternalReferencesCsvContent),
        indicatorsWithExternalReferencesCsvMapper as CsvMapperParsed
      );
      const {id: _expectedId, ...expectedRest} = indicatorsWithExternalReferencesExpectedBundle
      const indicatorsWithExternalReferencesExpectedBundleWithoutId = {...expectedRest}
      const {id: _actualId, ...actualRest} = indicatorsWithExternalReferencesActualBundle
      const indicatorsWithExternalReferencesActualBundleWithoutId = {...actualRest}
      expect(
        indicatorsWithExternalReferencesActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithExternalReferencesExpectedBundleWithoutId
      )
    })
    it('Should list labels', async () => {
      const indicatorsWithLabelsExpectedBundle: StixBundle = {
        id: "bundle--c8593959-d4b1-4ccf-95d5-bee644cf2c9b",
        spec_version: "2.1",
        type: "bundle",
        objects: [
          {
            color: "0b41f3",
            extensions: {
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3",
                extension_type: "new-sdo",
                type: "Label",
              },
            },
            id: "label--a70c2bda-5811-5dee-bd73-c19aa48f15df",
            spec_version: "2.1",
            type: "label",
            value: "filigran",
          },
          {
            extensions: {
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension",
              },
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.5'],IPv4-Addr,filigran,0b41f3",
                extension_type: "property-extension",
                labels_ids: [
                  undefined,
                ],
                main_observable_type: "IPv4-Addr",
                type: "Indicator",
              },
            },
            id: "indicator--c23d17a1-d085-51a3-8774-84627a986061",
            spec_version: "2.1",
            pattern_type: "stix",
            pattern: "[ipv4-addr:value = '198.168.8.5']",
            name: "[ipv4-addr:value = '198.168.8.5']",
            labels: [
              "filigran"
            ],
            type: "indicator"
          },
          {
            extensions: {
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension",
              },
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.6'],IPv4-Addr,filigran,0b41f3",
                extension_type: "property-extension",
                labels_ids: [
                  undefined,
                ],
                main_observable_type: "IPv4-Addr",
                type: "Indicator",
              },
            },
            id: "indicator--62a69445-3d8e-5ade-9f75-986ab8ce5494",
            spec_version: "2.1",
            pattern_type: "stix",
            pattern: "[ipv4-addr:value = '198.168.8.6']",
            name: "[ipv4-addr:value = '198.168.8.6']",
            labels: [
              "filigran"
            ],
            type: "indicator"
          }
        ] as unknown as StixDomainObject[]
      }
      const indicatorsWithLabelsActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        Buffer.from(indicatorsWithLabelsCsvContent),
        indicatorsWithLabelsCsvMapper as CsvMapperParsed
      )
      const {id: _expectedId, ...expectedRest} = indicatorsWithLabelsExpectedBundle
      const indicatorsWithLabelsExpectedBundleWithoutId = {...expectedRest}
      const {id: _actualId, ...actualRest} = indicatorsWithLabelsActualBundle
      const indicatorsWithLabelsActualBundleWithoutId = {...actualRest}
      expect(
        indicatorsWithLabelsActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithLabelsExpectedBundleWithoutId
      )
    })
    it('Should list kill chain phases', async () => {
      const indicatorsWithKillChainPhasesExpectedBundle: StixBundle = {
        id: "bundle--a58ed5eb-8881-475f-933a-098221a2052f",
        spec_version: "2.1",
        type: "bundle",
        objects: [
          {
            extensions: {
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.3'],IPv4-Addr,kill_chain_name_1,kill_chain_phase_name_1,1",
                extension_type: "new-sdo",
                type: "Kill-Chain-Phase",
              },
            },
            id: "kill-chain-phase--e0cf81cd-fad2-5e07-bed5-06d4556e8ac1",
            kill_chain_name: "kill_chain_name_1",
            order: 1,
            phase_name: "kill_chain_phase_name_1",
            spec_version: "2.1",
            type: "kill-chain-phase",
          },
          {
            extensions: {
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension",
              },
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.3'],IPv4-Addr,kill_chain_name_1,kill_chain_phase_name_1,1",
                extension_type: "property-extension",
                main_observable_type: "IPv4-Addr",
                type: "Indicator",
              },
            },
            id: "indicator--71e02a09-dea3-5336-ade3-9f397e6f1184",
            kill_chain_phases: [
              {
                kill_chain_name: "kill_chain_name_1",
                phase_name: "kill_chain_phase_name_1",
              },
            ],
            name: "[ipv4-addr:value = '198.168.8.3']",
            pattern: "[ipv4-addr:value = '198.168.8.3']",
            pattern_type: "stix",
            spec_version: "2.1",
            type: "indicator",
          },
          {
            extensions: {
              "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                extension_type: "property-extension",
              },
              "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                converter_csv: "[ipv4-addr:value = '198.168.8.4'],IPv4-Addr,kill_chain_name_1,kill_chain_phase_name_1,1",
                extension_type: "property-extension",
                main_observable_type: "IPv4-Addr",
                type: "Indicator",
              },
            },
            id: "indicator--43f6ef9e-ea3c-5e64-9898-f635ead37622",
            kill_chain_phases: [
              {
                kill_chain_name: "kill_chain_name_1",
                phase_name: "kill_chain_phase_name_1",
              },
            ],
            name: "[ipv4-addr:value = '198.168.8.4']",
            pattern: "[ipv4-addr:value = '198.168.8.4']",
            pattern_type: "stix",
            spec_version: "2.1",
            type: "indicator",
          },
        ] as unknown as StixDomainObject[],
      }
      const indicatorsWithKillChainPhasesActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        Buffer.from(indicatorsWithKillChainPhasesCsvContent),
        indicatorsWithKillChainPhasesCsvMapper as CsvMapperParsed
      )
      const {id: _expectedId, ...expectedRest} = indicatorsWithKillChainPhasesExpectedBundle
      const indicatorsWithKillChainPhasesExpectedBundleWithoutId = {...expectedRest}
      const {id: _actualId, ...actualRest} = indicatorsWithKillChainPhasesActualBundle
      const indicatorsWithKillChainPhasesActualBundleWithoutId = {...actualRest}
      expect(
        indicatorsWithKillChainPhasesActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithKillChainPhasesExpectedBundleWithoutId
      )
    })
  })
})