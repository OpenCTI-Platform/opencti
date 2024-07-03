import { describe, it, expect } from 'vitest';
import { bundleProcess } from '../../../src/parser/csv-bundler';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { indicatorsWithExternalReferencesCsvContent, indicatorsWithExternalReferencesCsvMapper } from '../../data/csv-bundler/external-references-constants';
  indicatorsWithExternalReferencesExpectedBundle
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { indicatorsWithLabelsCsvContent, indicatorsWithLabelsCsvMapper, indicatorsWithLabelsExpectedBundle } from '../../data/csv-bundler/labels-constants';
import {
  indicatorsWithKillChainPhasesCsvContent,
  indicatorsWithKillChainPhasesCsvMapper,
  indicatorsWithKillChainPhasesExpectedBundle
} from '../../data/csv-bundler/kill-chains-constants';

describe('CSV bundler', () => {
  describe('Embedded properties', () => {
    it('Should list external references', async () => {
        id: 'bundle--bfb3d6f4-6961-4fd0-8fb6-afbcbf2e0d59',
        spec_version: '2.1',
        type: 'bundle',
          {
            id: 'indicator--7be2cb5d-ec2b-5bdd-89eb-5802b71faabd',
            spec_version: '2.1',
            type: 'indicator',
            extensions: {
              'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
                extension_type: 'property-extension',
                type: 'Indicator',
                main_observable_type: 'IPv4-Addr',
                converter_csv: "[ipv4-addr:value = '198.168.8.1'],IPv4-Addr,http://twitter.com/filigraner"
              },
              'extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b': {
                extension_type: 'property-extension'
              }
            },
            external_references: [
              {
                source_name: 'http://twitter.com/filigraner',
                url: 'http://twitter.com/filigraner'
              }
            ],
            name: "[ipv4-addr:value = '198.168.8.1']",
            pattern: "[ipv4-addr:value = '198.168.8.1']",
            pattern_type: 'stix'
          },
          {
            id: 'indicator--adf3f1be-c67d-5f8a-85fb-3668f411d8b8',
            spec_version: '2.1',
            type: 'indicator',
            extensions: {
              'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
                extension_type: 'property-extension',
                type: 'Indicator',
                main_observable_type: 'IPv4-Addr',
                converter_csv: "[ipv4-addr:value = '198.168.8.2'],IPv4-Addr,http://twitter.com/filigraner"
              },
              'extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b': {
                extension_type: 'property-extension'
              }
            },
            external_references: [
              {
                source_name: 'http://twitter.com/filigraner',
                url: 'http://twitter.com/filigraner'
              }
            ],
            name: "[ipv4-addr:value = '198.168.8.2']",
            pattern: "[ipv4-addr:value = '198.168.8.2']",
            pattern_type: 'stix'
          }
      };
      const indicatorsWithExternalReferencesActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        indicatorsWithExternalReferencesCsvContent,
        indicatorsWithExternalReferencesCsvMapper as CsvMapperParsed
      );
      const { id: _expectedId, ...expectedRest } = indicatorsWithExternalReferencesExpectedBundle;
      const indicatorsWithExternalReferencesExpectedBundleWithoutId = { ...expectedRest };
      const { id: _actualId, ...actualRest } = indicatorsWithExternalReferencesActualBundle;
      const indicatorsWithExternalReferencesActualBundleWithoutId = { ...actualRest };
      expect(
        indicatorsWithExternalReferencesActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithExternalReferencesExpectedBundleWithoutId
      );
    });
  });
});

        ADMIN_USER,
        Buffer.from(indicatorsWithLabelsCsvContent),
        indicatorsWithLabelsCsvMapper as CsvMapperParsed
      );
      const { id: _expectedId, ...expectedRest } = indicatorsWithLabelsExpectedBundle;
      const indicatorsWithLabelsExpectedBundleWithoutId = { ...expectedRest };
      const { id: _actualId, ...actualRest } = indicatorsWithLabelsActualBundle;
      const indicatorsWithLabelsActualBundleWithoutId = { ...actualRest };
      expect(
        indicatorsWithLabelsActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithLabelsExpectedBundleWithoutId
      );
    });
    it('Should list kill chain phases', async () => {
      const indicatorsWithKillChainPhasesActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        Buffer.from(indicatorsWithKillChainPhasesCsvContent),
        indicatorsWithKillChainPhasesCsvMapper as CsvMapperParsed
      );
      const { id: _expectedId, ...expectedRest } = indicatorsWithKillChainPhasesExpectedBundle;
      const indicatorsWithKillChainPhasesExpectedBundleWithoutId = { ...expectedRest };
      const { id: _actualId, ...actualRest } = indicatorsWithKillChainPhasesActualBundle;
      const indicatorsWithKillChainPhasesActualBundleWithoutId = { ...actualRest };
      expect(
        indicatorsWithKillChainPhasesActualBundleWithoutId
      ).toStrictEqual(
        indicatorsWithKillChainPhasesExpectedBundleWithoutId
      );
    });
  });
});
