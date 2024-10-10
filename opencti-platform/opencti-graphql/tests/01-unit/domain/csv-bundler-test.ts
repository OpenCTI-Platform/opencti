import { describe, it, expect } from 'vitest';
import { bundleProcess, bundleProcessV2 } from '../../../src/parser/csv-bundler';
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
import { citiesWithTwoLabelsCsvMapper } from '../../data/csv-bundler/cities-with-two-labels-constants';
import { BundleBuilder, deduplicatedBundleData } from '../../../src/parser/bundle-creator';
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
    it('Should split same city with different label in 2 valid bundles', async () => {
      // duplicate should be removed, unless label are different.
      const citiesWithTwoLabels:string[] = [
        'name,label,color',
        'Lyon,label1,#ffffff',
        'Lyon,label2,#000000',
        'Grenoble,label2,#000000',
        'Grenoble,label2,#000000',
      ];

      const bundleResult: BundleBuilder[] = await bundleProcessV2(
        testContext,
        ADMIN_USER,
        citiesWithTwoLabels,
        citiesWithTwoLabelsCsvMapper as CsvMapperParsed
      );

      expect(bundleResult.length).toBe(2);
      const firstBundle = bundleResult[0].build();
      expect(firstBundle.objects.length).toBe(4); // 2 labels + 2 cities

      const secondBundle = bundleResult[1].build();
      expect(secondBundle.objects.length).toBe(2); // Only Lyon + label2
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
