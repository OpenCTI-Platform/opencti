import { describe, it, expect } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import {
  indicatorsWithExternalReferencesCsvContent,
  indicatorsWithExternalReferencesCsvMapper,
  indicatorsWithExternalReferencesExpectedBundle
} from './csv-bundler-data/external-references-constants';
import { type CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import { indicatorsWithLabelsCsvContent, indicatorsWithLabelsCsvMapper, indicatorsWithLabelsExpectedBundle } from './csv-bundler-data/labels-constants';
import {
  indicatorsWithKillChainPhasesCsvContent,
  indicatorsWithKillChainPhasesCsvMapper,
  indicatorsWithKillChainPhasesExpectedBundle
} from './csv-bundler-data/kill-chains-constants';
import { citiesWithTwoLabelsCsvMapper } from './csv-bundler-data/cities-with-two-labels-constants';
import { BundleBuilder } from '../../../src/parser/bundle-creator';
import type { StixBundle, StixObject } from '../../../src/types/stix-common';
import type { StixLabel } from '../../../src/types/stix-smo';
import type { StixLocation, StixThreatActor } from '../../../src/types/stix-sdo';
import { emailWithTwoDescCsvMapper } from './csv-bundler-data/email-with-two-descp-constants';
import { type CsvBundlerTestOpts, generateTestBundle } from '../../../src/parser/csv-bundler';
import { csvMapperDynamicIpAndThreatActor } from './csv-bundler-data/mapper-threatactor-ip';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../../src/schema/general';
import { logApp } from '../../../src/config/conf';

describe('CSV bundler', () => {
  describe('Embedded properties', () => {
    it('Should list external references', async () => {
      // because csv has_header=true is managed outside
      const csvLines = indicatorsWithExternalReferencesCsvContent;
      csvLines.shift();
      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: indicatorsWithExternalReferencesCsvMapper as CsvMapperParsed
      };
      const allBundleBuilder = await generateTestBundle(testContext, csvLines, bundlerOpts);
      expect(allBundleBuilder.length).toBe(1);
      const indicatorsWithExternalReferencesActualBundle: StixBundle = allBundleBuilder[0].build();

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
      const csvLines = indicatorsWithLabelsCsvContent;
      csvLines.shift();

      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: indicatorsWithLabelsCsvMapper as CsvMapperParsed
      };

      const allBundleBuilder = await generateTestBundle(testContext, csvLines, bundlerOpts);

      expect(allBundleBuilder.length).toBe(1);
      const indicatorsWithLabelsActualBundle = allBundleBuilder[0].build();
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
      const csvLines = indicatorsWithKillChainPhasesCsvContent;
      csvLines.shift();

      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: indicatorsWithKillChainPhasesCsvMapper as CsvMapperParsed
      };

      const allBundleBuilder = await generateTestBundle(testContext, csvLines, bundlerOpts);
      const indicatorsWithKillChainPhasesActualBundle = allBundleBuilder[0].build();
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
    it('Should split same city with different label in 2 valid bundles (testing SDO)', async () => {
      // duplicate should be removed, unless label are different.
      const citiesWithTwoLabels:string[] = [
        'Lyon,label1,#ffffff',
        'Lyon,label2,#000000',
        'Grenoble,label2,#000000',
        'Grenoble,label2,#000000',
      ];
      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: citiesWithTwoLabelsCsvMapper as CsvMapperParsed
      };
      const bundleResult: BundleBuilder[] = await generateTestBundle(testContext, citiesWithTwoLabels, bundlerOpts);

      expect(bundleResult.length).toBe(2);
      const firstBundle = bundleResult[0].build();
      expect(firstBundle.objects.length).toBe(2); // Lyon,label1,#ffffff = 1 city (Lyon) + 1 Label (label 1)

      const secondBundle = bundleResult[1].build();
      expect(secondBundle.objects.length).toBe(3); // Only Lyon + Grenoble + label2
    });
    it('Should split same email address with different label in 2 valid bundles (testing SCO)', async () => {
      // duplicate should be removed, unless descriptions are different.
      const emailsWithTwoDescriptions:string[] = [
        'ada.lovelace@opencti.io,First programmer ever',
        'ada.lovelace@opencti.io,First programmer ever on top of Turing work.',
      ];
      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: emailWithTwoDescCsvMapper as CsvMapperParsed
      };
      const bundleResult: BundleBuilder[] = await generateTestBundle(testContext, emailsWithTwoDescriptions, bundlerOpts);

      const firstBundle = bundleResult[0].build();
      expect(firstBundle.objects.length).toBe(1);

      const secondBundle = bundleResult[1].build();
      expect(secondBundle.objects.length).toBe(1);
    });

    it('Should confidence level not prevent upsert of last data', async () => {
      // In mapper last column is mapped as confidence.
      const threatActorAndIpWithConfidence:string[] = [
        'myNewThreatActor,WowDedup,#acff33,a great description,threat,100',
        'myNewThreatActor,Magic,#33ff42,This is a description that should stay,threat,65',
      ];

      const bundlerOpts : CsvBundlerTestOpts = {
        applicantUser: ADMIN_USER,
        csvMapper: csvMapperDynamicIpAndThreatActor as CsvMapperParsed
      };

      const bundleResult: BundleBuilder[] = await generateTestBundle(testContext, threatActorAndIpWithConfidence, bundlerOpts);
      expect(bundleResult.length).toBe(2); // one bundler per line since it's same theat actor name.

      const firstBundle = bundleResult[0].build();
      logApp.info('firstBundle:', firstBundle);
      // 'myNewThreatActor,WowDedup,#acff33,a great description,threat,100',
      const firstBundleThreatActor = firstBundle.objects.find((object) => object.type === ENTITY_TYPE_THREAT_ACTOR.toLowerCase()) as StixThreatActor;
      expect(firstBundleThreatActor.name).toBe('myNewThreatActor');
      const firstBundleLabel = firstBundle.objects.find((object) => object.type === ENTITY_TYPE_LABEL.toLowerCase()) as StixLabel;
      expect(firstBundleLabel.value).toBe('WowDedup');

      const secondBundle = bundleResult[1].build();
      // 'myNewThreatActor,Magic,#33ff42,This is a description that should stay,threat,65',
      const secondBundleIP = secondBundle.objects.find((object) => object.type === ENTITY_TYPE_THREAT_ACTOR.toLowerCase()) as StixThreatActor;
      expect(secondBundleIP.name).toBe('myNewThreatActor');
      const secondBundleLabel = secondBundle.objects.find((object) => object.type === ENTITY_TYPE_LABEL.toLowerCase()) as StixLabel;
      expect(secondBundleLabel.value).toBe('Magic');
    });
  });

  describe('BundleBuilder testing canAdd checks', () => {
    it('Should request a new bundle when id already exists but with different data', async () => {
      const objectsInBundle: StixObject[] = [
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
        } as unknown as StixLocation
      ];

      // For exemple different label
      const newObjectsLabels: StixObject[] = [
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
        } as unknown as StixLocation
      ];

      const bundleBuilder = new BundleBuilder();
      bundleBuilder.addObjects(objectsInBundle, 'ville du pont;label2');
      expect(bundleBuilder.canAddObjects(newObjectsLabels)).toBeFalsy();

      // For example different description
      const newObjectsDesc: StixObject[] = [
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
          type: 'location',
          description: 'new data in the same entity id'
        } as unknown as StixLocation
      ];

      expect(bundleBuilder.canAddObjects(newObjectsDesc)).toBeFalsy();
    });

    it('Should not request a new bundle when id are new', async () => {
      const objectsInBundle: StixObject[] = [
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
        } as unknown as StixLocation
      ];

      const newObjects: StixObject[] = [
        {
          color: '#ffffff',
          id: 'label--1c284682-f33e-5c37-9bad-9820cb37ee2a',
          spec_version: '2.1',
          type: 'label',
          value: 'label1'
        } as unknown as StixLabel,
        {
          city: 'ville du pont2',
          id: 'location--542797f4-36b0-5404-8a1b-05da43029faa',
          labels: ['label1'],
          latitude: 45.999873398,
          longitude: 5.498147193,
          name: 'ville du pont2',
          spec_version: '2.1',
          type: 'location'
        } as unknown as StixLocation
      ];
      const bundleBuilder = new BundleBuilder();
      bundleBuilder.addObjects(objectsInBundle, 'ville du pont;label2');
      expect(bundleBuilder.canAddObjects(newObjects)).toBeTruthy();
    });

    it('Should not request a new bundle when object are exactly the same', async () => {
      const objectsInBundle: StixObject[] = [
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
        } as unknown as StixLocation
      ];

      const newObjects: StixObject[] = [
        {
          color: '#000000',
          id: 'label--ad140703-c0bd-5572-818e-b480708034b5',
          spec_version: '2.1',
          type: 'label',
          value: 'label2',
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
        } as unknown as StixLocation
      ];

      const bundleBuilder = new BundleBuilder();
      bundleBuilder.addObjects(objectsInBundle, 'ville du pont;label2');
      expect(bundleBuilder.canAddObjects(newObjects)).toBeTruthy();
    });
  });
});
