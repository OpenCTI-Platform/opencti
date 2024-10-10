import { describe, it, expect } from 'vitest';
import { bundleProcess } from '../../../src/parser/csv-bundler';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import {
  indicatorsWithExternalReferencesCsvContent,
  indicatorsWithExternalReferencesCsvMapper,
  indicatorsWithExternalReferencesExpectedBundle
} from '../../data/csv-bundler/external-references-constants';
import { type CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { indicatorsWithLabelsCsvContent, indicatorsWithLabelsCsvMapper, indicatorsWithLabelsExpectedBundle } from '../../data/csv-bundler/labels-constants';
import {
  indicatorsWithKillChainPhasesCsvContent,
  indicatorsWithKillChainPhasesCsvMapper,
  indicatorsWithKillChainPhasesExpectedBundle
} from '../../data/csv-bundler/kill-chains-constants';
import { citiesWithTwoLabels, citiesWithTwoLabelsCsvMapper } from '../../data/csv-bundler/cities-with-two-labels-constants';
import { logApp } from '../../../src/config/conf';
import { deduplicatedBundleData } from '../../../src/parser/bundle-creator';
import type { StixObject } from '../../../src/types/stix-common';
import type { StixLabel } from '../../../src/types/stix-smo';
import type { StixLocation } from '../../../src/types/stix-sdo';

describe('CSV bundler', () => {
  describe('Embedded properties', () => {
    it('Should list external references', async () => {
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
    it('Should list labels', async () => {
      const indicatorsWithLabelsActualBundle = await bundleProcess(
        testContext,
        ADMIN_USER,
        indicatorsWithLabelsCsvContent,
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
        indicatorsWithKillChainPhasesCsvContent,
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
    it('Should send all', async () => {
      const bundleResult = await bundleProcess(
        testContext,
        ADMIN_USER,
        citiesWithTwoLabels,
        citiesWithTwoLabelsCsvMapper as CsvMapperParsed
      );
      logApp.info('ANGIE - bundleResult:', { bundleResult });
    });
  });

  describe('BundleBuilder testing deduplicatedBundleData', () => {
    it('Should do nothing when no duplicated ids', async () => {
      const inputArray: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: [
            'label1'
          ],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#000000',
          id: 'label--ad140703-c0bd-5572-818e-b480708034b5',
          spec_version: '2.1',
          type: 'label',
          value: 'label2'
        } as unknown as StixLabel,
      ];

      const expectedResult: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: [
            'label1'
          ],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#000000',
          id: 'label--ad140703-c0bd-5572-818e-b480708034b5',
          spec_version: '2.1',
          type: 'label',
          value: 'label2'
        } as unknown as StixLabel,
      ];

      expect(deduplicatedBundleData(inputArray)).toStrictEqual(expectedResult);
    });

    it('Should remove duplicated data', async () => {
      const inputArray: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: [
            'label1'
          ],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
      ];

      const expectedResult: StixObject[] = [{
        color: '#ffffff',
        id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
        spec_version: '2.1',
        type: 'label',
        value: 'label1'
      } as unknown as StixLabel,
      {
        city: 'ville du pont',
        id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
        labels: [
          'label1'
        ],
        latitude: 46.999873398,
        longitude: 6.498147193,
        name: 'ville du pont',
        spec_version: '2.1',
        type: 'location'
      } as unknown as StixLocation
      ];

      expect(deduplicatedBundleData(inputArray)).toStrictEqual(expectedResult);
    });

    it('Should remove duplicated ids except when labels differs', async () => {
      const inputArray: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: ['label1'],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#000000',
          id: 'label--ad140703-c0bd-5572-818e-b480708034b5',
          spec_version: '2.1',
          type: 'label',
          value: 'label2'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: ['label2'],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
      ];

      const expectedResult: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: ['label1'],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
        {
          color: '#000000',
          id: 'label--ad140703-c0bd-5572-818e-b480708034b5',
          spec_version: '2.1',
          type: 'label',
          value: 'label2'
        } as unknown as StixLabel,
        {
          city: 'ville du pont',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029f13',
          labels: ['label2'],
          latitude: 46.999873398,
          longitude: 6.498147193,
          name: 'ville du pont',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation,
      ];

      expect(deduplicatedBundleData(inputArray)).toStrictEqual(expectedResult);
    });
  });
});
