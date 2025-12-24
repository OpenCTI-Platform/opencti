import { describe, expect, it } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_CONNECTOR_COMPONENT } from '../../../../src/modules/playbook/playbook-components';

describe('PLAYBOOK_ENRICH_CONNECTOR_COMPONENT', () => {
  const baseBundle: StixBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--id',
    objects: []
  } as StixBundle;

  const ipv4ObjectId = 'bundle--ipv4-id';

  const baseBundleObject = {
    type: 'sco',
    spec_version: '2.1',
    id: ipv4ObjectId,
    name: 'Playbook Object 1',
    extensions: {
      [STIX_EXT_OCTI]: {
        id: 'internal-uuid',
        type: 'IPv4-Addr',
        extension_type: 'property-extension'
      }
    }
  };

  const baseExecutorParams = {
    ipv4ObjectId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
  };

  const dummyPlaybookNode = {
    id: 'playbook-node',
    name: 'node',
    component_id: 'test',
    configuration: {
      all: false,
      connector: 'virus-total'
    }
  };

  it('should add previousStepBundle objects that are not present in the new bundle', async () => {
    const idInBoth = 'sco--in-both';
    const idOnlyInPrevious = 'sco--only-in-previous';

    const previousStepBundle: StixBundle = {
      ...baseBundle,
      id: 'bundle--previous',
      objects: [
        {
          id: idInBoth,
          type: 'sco',
          spec_version: '2.1',
          name: 'Object in both bundles',
          extensions: {
            [STIX_EXT_OCTI]: {
              id: 'ext-both',
              type: 'sco',
              extension_type: 'property-extension',
              labels_ids: ['label-in-both']
            } as StixOpenctiExtension
          }
        } as StixObject,
        {
          id: idOnlyInPrevious,
          type: 'sco',
          spec_version: '2.1',
          name: 'Object only in previous bundle',
          extensions: {
            [STIX_EXT_OCTI]: {
              id: 'ext-prev-only',
              type: 'sco',
              extension_type: 'property-extension',
              labels_ids: ['label-prev-only']
            } as StixOpenctiExtension
          }
        } as StixObject
      ]
    };

    const bundle: StixBundle = {
      ...baseBundle,
      id: 'bundle--current',
      objects: [
        {
          id: idInBoth,
          type: 'sco',
          spec_version: '2.1',
          name: 'Object in both bundles (current)',
          extensions: {
            [STIX_EXT_OCTI]: {
              id: 'ext-both',
              type: 'sco',
              extension_type: 'property-extension',
              labels_ids: ['label-in-both']
            } as StixOpenctiExtension
          }
        } as StixObject
      ]
    };

    const result = await PLAYBOOK_CONNECTOR_COMPONENT.executor({
      ...baseExecutorParams,
      dataInstanceId: idInBoth,
      previousStepBundle,
      bundle,
      playbookNode: dummyPlaybookNode
    });

    const resultIds = result.bundle.objects.map((o: StixObject) => o.id);

    expect(resultIds).toContain(idInBoth);
    expect(resultIds).toContain(idOnlyInPrevious);
    const added = result.bundle.objects.find((o) => o.id === idOnlyInPrevious) as StixObject;
    const addedExt = added.extensions![STIX_EXT_OCTI] as StixOpenctiExtension;
    expect(addedExt.labels_ids).toEqual(['label-prev-only']);
  });

  it('should merge previousStepBundle objects and new bundle objects with same id', async () => {
    const previousStepBundle = {
      ...baseBundle,
      objects: [{
        ...baseBundleObject,
        labels: ['label-id-1'],
        extensions: {
          [STIX_EXT_OCTI]: {
            id: 'some--id',
            type: 'sco',
            extension_type: 'property-extension',
            labels_ids: ['label-id-1']
          } as StixOpenctiExtension
        }
      } as StixObject]
    } as StixBundle;

    const bundle = {
      ...baseBundle,
      objects: [{
        ...baseBundleObject,
        labels: ['label-id-2'],
        extensions: {
          [STIX_EXT_OCTI]: {
            id: 'some--id',
            type: 'sco',
            extension_type: 'property-extension',
            labels_ids: ['label-id-2'],
          } as StixOpenctiExtension
        }
      } as StixObject]
    } as StixBundle;

    const result = await PLAYBOOK_CONNECTOR_COMPONENT.executor({
      dataInstanceId: '',
      ...baseExecutorParams,
      previousStepBundle,
      bundle,
      playbookNode: dummyPlaybookNode
    });
    const extensions = result.bundle.objects.map((object) => object.extensions[STIX_EXT_OCTI]);
    expect(extensions).toHaveLength(1);
    expect(extensions[0].labels_ids).toEqual(['label-id-1', 'label-id-2']);  });
});