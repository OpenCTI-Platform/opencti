import { assert, describe, expect, it } from 'vitest';
import type { StixBundle, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixThreatActor } from '../../../../src/types/stix-2-1-sdo';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import { ENTITY_TYPE_THREAT_ACTOR } from '../../../../src/schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';

describe('PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT', () => {
  const baseBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--threat-id',
  } as StixBundle;

  const threatObjectId = 'threat--obj-uuid';
  const dataInstanceId = threatObjectId;

  const baseBundleObject = {
    type: 'threat',
    spec_version: '2.1',
    id: threatObjectId,
    name: 'Playbook Object 1',
    extensions: {
      [STIX_EXT_OCTI]: {
        id: 'internal-uuid',
        type: ENTITY_TYPE_THREAT_ACTOR,
        extension_type: 'property-extension'
      }
    }
  } as unknown as StixThreatActor;
  const basePlaybookNode = {
    id: 'playbook-node-1',
    name: 'Update Knowledge Node',
    component_id: 'test-node-1',
  };

  const baseExecutorParams = {
    dataInstanceId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
  };

  it('should remove labels by field patch', async () => {
    const bundle = {
      ...baseBundle,
      objects: [{
        ...baseBundleObject,
        labels: ['unicorn', 'honey badger', 'pangolin'],
        extensions: {
          [STIX_EXT_OCTI] : {
            id: 'some--id',
            type: ENTITY_TYPE_CONTAINER_REPORT,
            extension_type: 'property-extension',
            labels_ids: ['unicorn-id','honey-badger-id','pangolin-id']
          } as StixOpenctiExtension
        }
      } as StixObject]
    } as StixBundle;

    const playbookNode = {
      ...basePlaybookNode,
      configuration: {
        all: false,
        actions: [
          {
            op: 'remove' as const,
            attribute: 'objectLabel',
            value: [
              {
                label: 'Unicorn',
                value: 'unicorn-id',
                patch_value: 'unicorn'
              },
              {
                label: 'Honey badger',
                value: 'honey-badger-id',
                patch_value: 'honey badger'
              }
            ]
          }
        ]
      }
    };

    const result = await PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.executor({
      ...baseExecutorParams,
      previousStepBundle: bundle,
      dataInstanceId: threatObjectId,
      playbookNode,
      bundle
    });

    const updatedActor = result.bundle.objects.find(o => o.id === threatObjectId) as StixThreatActor;
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
    const bundle = {
      ...baseBundle,
      objects: [{
        ...baseBundleObject,
        confidence: '15'
      } as StixObject]
    } as StixBundle;

    const playbookNode1 = {
      ...basePlaybookNode,
      configuration: {
        all: false,
        actions: [
          {
            op: 'replace' as const,
            attribute: 'confidence',
            value: [
              {
                label: 'Set confidence to 75',
                value: '75',
                patch_value: '75'
              }
            ]
          }
        ]
      }
    };

    const playbookNode2 = {
      ...basePlaybookNode,
      configuration: {
        all: false,
        actions: [
          {
            op: 'add' as const,
            attribute: 'objectMarking',
            value: [
              {
                label: 'PAP:GREEN',
                value: 'pap-green-id',
                patch_value: 'pap-green-id'
              }
            ]
          }
        ]
      }
    };

    const result1 = await PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.executor({
      ...baseExecutorParams,
      previousStepBundle: bundle,
      dataInstanceId: threatObjectId,
      playbookNode: playbookNode1,
      bundle
    });
    const result2 = await PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.executor({
      ...baseExecutorParams,
      previousStepBundle: bundle,
      dataInstanceId: threatObjectId,
      playbookNode: playbookNode2,
      bundle: result1.bundle
    });

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

    const updatedActor = result2.bundle.objects.find(o => o.id === threatObjectId) as StixThreatActor;
    expect(updatedActor.confidence).toBe(75);
    expect(updatedActor.object_marking_refs).toEqual(['pap-green-id']);
  });
});
