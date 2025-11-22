import { assert, describe, expect, it } from 'vitest';
import type {StixBundle} from '../../../../src/types/stix-2-1-common';
import {PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT,} from "../../../../src/modules/playbook/playbook-components";
import {STIX_EXT_OCTI} from "../../../../src/types/stix-2-1-extensions";
import type {StixThreatActor} from "../../../../src/types/stix-2-1-sdo";
import type {StixObject} from "../../../../src/types/stix-2-1-common";
import {ENTITY_TYPE_THREAT_ACTOR} from "../../../../src/schema/general";


describe('PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT', () => {
  const baseBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--threat-id',
  } as StixBundle;

  const threatObjectId = 'threat--obj-uuid';
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
  } as unknown as StixThreatActor

  const basePlaybookNode = {
    id: 'playbook-node-1',
    name: 'Update Knowledge Node',
    component_id: 'test-node-1',
  };

  const dataInstanceId = threatObjectId;
  const baseExecutorParams = {
    dataInstanceId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
  }

  it.skip('should replace the confidence attribute using field patch', async () => {
    const bundle = {
      ...baseBundle,
      objects: [{
        ...baseBundleObject,
        confidence: '15'
      } as StixObject]
    } as StixBundle

    const playbookNode = {
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
    }

    const result = await PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.executor({
      ...baseExecutorParams,
      previousStepBundle: bundle,
      dataInstanceId: threatObjectId,
      playbookNode,
      bundle
    });

    const updatedActor = result.bundle.objects.find(o => o.id === threatObjectId) as StixThreatActor;
    const objectExtensions = result.bundle.objects[0].extensions[STIX_EXT_OCTI]
    if (!objectExtensions.opencti_field_patch || !objectExtensions.opencti_field_patch[0]) {
      assert.fail("Field patch missing");
    }
    expect(objectExtensions.opencti_operation).toBe('patch');
    expect(objectExtensions.opencti_field_patch[0].operation).toBe('replace');
    expect(objectExtensions.opencti_field_patch[0].key).toBe('confidence');
    expect(objectExtensions.opencti_field_patch[0].value[0]).toBe('75');

    expect(updatedActor.confidence).toBe(75);
  });

});
