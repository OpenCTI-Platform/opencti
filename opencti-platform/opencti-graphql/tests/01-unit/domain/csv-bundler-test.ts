import { describe, it, expect } from 'vitest';
import { bundleProcess } from '../../../src/parser/csv-bundler';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import {
  indicatorsWithExternalReferencesCsvContent,
  indicatorsWithExternalReferencesCsvMapper,
  indicatorsWithExternalReferencesExpectedBundle
} from '../../data/csv-bundler/external-references-constants';
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
      const indicatorsWithExternalReferencesActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        Buffer.from(indicatorsWithExternalReferencesCsvContent),
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
    it('Should list labels', async () => {
      const indicatorsWithLabelsActualBundle = await bundleProcess(
        testContext,
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
