import { assert, describe, expect, it } from 'vitest';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixThreatActor } from '../../../../src/types/stix-2-1-sdo';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../../../src/schema/general';
import { PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT, type ManipulateConfiguration } from '../../../../src/modules/playbook/components/manipulate-knowledge-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';

describe('PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT', () => {
  const THREAT_ACTOR_ID = 'threat--09bd862a-f030-55f2-920a-900c4913d9fd';

  it('should replace labels by field patch', async () => {
    const bundleObjects = [testBundleObject<StixThreatActor>({
      id: THREAT_ACTOR_ID,
      type: ENTITY_TYPE_THREAT_ACTOR,
      labels: ['unicorn', 'honey badger', 'pangolin'],
      octiExtension: {
        labels_ids: ['unicorn-id', 'honey-badger-id', 'pangolin-id'],
      },
    })];

    const configuration: ManipulateConfiguration = {
      applyToElements: 'only-main',
      actions: [{
        op: 'replace' as const,
        attribute: 'objectLabel',
        value: [
          {
            label: 'Unicorn',
            value: 'unicorn-id',
            patch_value: 'unicorn',
          },
          {
            label: 'Honey badger',
            value: 'honey-badger-id',
            patch_value: 'honey badger',
          },
        ],
      }],
    };

    const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
      mainId: THREAT_ACTOR_ID,
      bundleObjects,
      configuration,
    }));

    const updatedActor = result.bundle.objects.find((o) => o.id === THREAT_ACTOR_ID) as StixThreatActor;
    const objectExtensions = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
    if (!objectExtensions.opencti_upsert_operations || !objectExtensions.opencti_upsert_operations[0]) {
      assert.fail('Field patch missing');
    }
    expect(objectExtensions.opencti_upsert_operations[0].operation).toBe('replace');
    expect(objectExtensions.opencti_upsert_operations[0].key).toBe('objectLabel');
    expect(objectExtensions.opencti_upsert_operations[0].value[0]).toBe('unicorn-id');
    expect(objectExtensions.opencti_upsert_operations[0].value[1]).toBe('honey-badger-id');
    expect(updatedActor.labels).toEqual(['unicorn', 'honey badger']);
  });

  it('should remove labels by field patch', async () => {
    const bundleObjects = [testBundleObject<StixThreatActor>({
      id: THREAT_ACTOR_ID,
      type: ENTITY_TYPE_THREAT_ACTOR,
      labels: ['unicorn', 'honey badger', 'pangolin'],
      octiExtension: {
        labels_ids: ['unicorn-id', 'honey-badger-id', 'pangolin-id'],
      },
    })];

    const configuration: ManipulateConfiguration = {
      applyToElements: 'only-main',
      actions: [{
        op: 'remove' as const,
        attribute: 'objectLabel',
        value: [
          {
            label: 'Unicorn',
            value: 'unicorn-id',
            patch_value: 'unicorn',
          },
          {
            label: 'Honey badger',
            value: 'honey-badger-id',
            patch_value: 'honey badger',
          },
        ],
      }],
    };

    const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
      mainId: THREAT_ACTOR_ID,
      bundleObjects,
      configuration,
    }));

    const updatedActor = result.bundle.objects.find((o) => o.id === THREAT_ACTOR_ID) as StixThreatActor;
    const objectExtensions = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
    if (!objectExtensions.opencti_upsert_operations || !objectExtensions.opencti_upsert_operations[0]) {
      assert.fail('Field patch missing');
    }
    expect(objectExtensions.opencti_upsert_operations[0].operation).toBe('remove');
    expect(objectExtensions.opencti_upsert_operations[0].key).toBe('objectLabel');
    expect(objectExtensions.opencti_upsert_operations[0].value[0]).toBe('unicorn-id');
    expect(objectExtensions.opencti_upsert_operations[0].value[1]).toBe('honey-badger-id');
    expect(updatedActor.labels).toEqual(['pangolin']);
  });

  it('should update 2 attributes in successive playbook nodes using field patches (confidence & marking definitions)', async () => {
    const bundleObjects = [testBundleObject<StixThreatActor>({
      id: THREAT_ACTOR_ID,
      type: ENTITY_TYPE_THREAT_ACTOR,
      confidence: 15,
    })];

    const result1 = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
      mainId: THREAT_ACTOR_ID,
      bundleObjects,
      configuration: {
        applyToElements: 'only-main',
        actions: [{
          op: 'replace' as const,
          attribute: 'confidence',
          value: [
            {
              label: 'Set confidence to 75',
              value: '75',
              patch_value: '75',
            },
          ],
        }],
      },
    }));

    const result2 = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
      mainId: THREAT_ACTOR_ID,
      bundle: result1.bundle,
      configuration: {
        applyToElements: 'only-main',
        actions: [{
          op: 'add' as const,
          attribute: 'objectMarking',
          value: [
            {
              label: 'PAP:GREEN',
              value: 'pap-green-id',
              patch_value: 'pap-green-id',
            },
          ],
        }],
      },
    }));

    const objectExtensions = result2.bundle.objects[0].extensions[STIX_EXT_OCTI];
    if (!objectExtensions.opencti_upsert_operations || !objectExtensions.opencti_upsert_operations[0]) {
      assert.fail('Field patch missing');
    }
    expect(objectExtensions.opencti_upsert_operations[0].operation).toBe('replace');
    expect(objectExtensions.opencti_upsert_operations[0].key).toBe('confidence');
    expect(objectExtensions.opencti_upsert_operations[0].value[0]).toBe('75');
    expect(objectExtensions.opencti_upsert_operations[1].operation).toBe('add');
    expect(objectExtensions.opencti_upsert_operations[1].key).toBe('objectMarking');
    expect(objectExtensions.opencti_upsert_operations[1].value[0]).toBe('pap-green-id');

    const updatedActor = result2.bundle.objects.find((o) => o.id === THREAT_ACTOR_ID) as StixThreatActor;
    expect(updatedActor.confidence).toBe(75);
    expect(updatedActor.object_marking_refs).toEqual(['pap-green-id']);
  });

  describe('Bundle scope', () => {
    const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
    const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';

    const BUNDLE_OBJECTS = () => [
      testBundleObject({
        id: MALWARE_ID,
        type: 'Malware',
      }),
      testBundleObject({
        id: CAMPAIGN_ID,
        type: 'Campaign',
      }),
    ];

    const componentConfig = (config?: Partial<ManipulateConfiguration>) => {
      return {
        applyToElements: 'only-main' as const,
        actions: [{
          op: 'add' as const,
          attribute: 'objectLabel',
          value: [{
            label: 'Duck',
            value: 'duck-id',
            patch_value: 'duck',
          }],
        }],
        ...config,
      };
    };

    it('should add label only on main element', async () => {
      const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
        mainId: MALWARE_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig(),
      }));

      const malwareResult = result.bundle.objects.find((o) => o.id === MALWARE_ID);
      const malwareExtensions = malwareResult?.extensions[STIX_EXT_OCTI];
      const campaignResult = result.bundle.objects.find((o) => o.id === CAMPAIGN_ID);
      const campaignExtensions = campaignResult?.extensions[STIX_EXT_OCTI];
      expect(malwareExtensions?.opencti_upsert_operations?.length).toEqual(1);
      expect(campaignExtensions?.opencti_upsert_operations).toBeUndefined();
    });

    it('should add label to all elements', async () => {
      const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
        mainId: MALWARE_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({ applyToElements: 'all-elements' }),
      }));

      const malwareResult = result.bundle.objects.find((o) => o.id === MALWARE_ID);
      const malwareExtensions = malwareResult?.extensions[STIX_EXT_OCTI];
      const campaignResult = result.bundle.objects.find((o) => o.id === CAMPAIGN_ID);
      const campaignExtensions = campaignResult?.extensions[STIX_EXT_OCTI];
      expect(malwareExtensions?.opencti_upsert_operations?.length).toEqual(1);
      expect(campaignExtensions?.opencti_upsert_operations?.length).toEqual(1);
    });

    it('should add label to all elements except main', async () => {
      const result = await PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.executor(testExecutor({
        mainId: MALWARE_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: componentConfig({ applyToElements: 'all-except-main' }),
      }));

      const malwareResult = result.bundle.objects.find((o) => o.id === MALWARE_ID);
      const malwareExtensions = malwareResult?.extensions[STIX_EXT_OCTI];
      const campaignResult = result.bundle.objects.find((o) => o.id === CAMPAIGN_ID);
      const campaignExtensions = campaignResult?.extensions[STIX_EXT_OCTI];
      expect(malwareExtensions?.opencti_upsert_operations).toBeUndefined();
      expect(campaignExtensions?.opencti_upsert_operations?.length).toEqual(1);
    });
  });
});
