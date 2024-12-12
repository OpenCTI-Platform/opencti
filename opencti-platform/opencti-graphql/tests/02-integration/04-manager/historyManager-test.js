import { describe, expect, it } from 'vitest';
import { INDEX_HISTORY } from '../../../src/database/utils';
import { buildHistoryElementsFromEvents, resolveGrantedRefsIds } from '../../../src/manager/historyManager';
import { ENTITY_TYPE_HISTORY } from '../../../src/schema/internalObject';
import { testContext } from '../../utils/testQuery';

const eventWithGrantedRefIds = {
  id: '1731595374948-0',
  event: 'update',
  data: {
    version: '4',
    type: 'update',
    scope: 'external',
    message: 'adds `Filigran` in `Shared with`',
    origin: {
      socket: 'query',
      ip: '::1',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      group_ids: ['9c746e48-28fd-432a-abd7-d7593eb310c4'],
      organization_ids: [],
      user_metadata: {},
      referer: 'http://localhost:3000/dashboard/analyses/reports/58fbfcfa-01ce-4440-8edf-7ea38e7a6ae9'
    },
    data: {
      id: 'report--d27398f3-8086-50e7-9c71-088b9bd69605',
      spec_version: '2.1',
      type: 'report',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: '58fbfcfa-01ce-4440-8edf-7ea38e7a6ae9',
          type: 'Report',
          created_at: '2024-02-20T15:34:17.203Z',
          updated_at: '2024-11-14T14:42:37.551Z',
          is_inferred: false,
          granted_refs: ['identity--67fabb23-c547-5c4a-b253-9d9a8548c466', 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29'],
          creator_ids: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
          granted_refs_ids: ['c080a677-f640-4643-9d2a-75929ac07b1c', '0c897410-3579-4770-b26e-1fce2e441204'],
          workflow_id: '78973513-cebc-49f9-a316-12487acd7903',
          labels_ids: ['7b705594-e2bc-48f8-bdc3-8c55ce1adb0e']
        }
      },
      created: '2024-02-20T15:34:11.000Z',
      modified: '2024-11-14T14:42:37.551Z',
      revoked: false,
      confidence: 100,
      lang: 'en',
      labels: ['label-debug-rename2'],
      name: 'test',
      published: '2024-02-20T15:34:11.000Z',
    },
    context: {
      patch: [
        { op: 'add', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs_ids/1', value: '0c897410-3579-4770-b26e-1fce2e441204' },
        { op: 'add', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs/1', value: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29' }
      ],
      reverse_patch: [
        { op: 'remove', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs_ids/1' },
        { op: 'remove', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs/1' }
      ]
    }
  }
};

const eventWithGrantedRefsOnly = {
  id: '1731597042395-0',
  event: 'update',
  data: {
    version: '4',
    type: 'update',
    scope: 'external',
    message: 'adds `TestOrganization` in `Shared with`',
    origin: {
      socket: 'query',
      ip: '::1',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      group_ids: ['9c746e48-28fd-432a-abd7-d7593eb310c4'],
      organization_ids: [],
      user_metadata: {},
      referer: 'http://localhost:3000/dashboard/analyses/reports/58fbfcfa-01ce-4440-8edf-7ea38e7a6ae9'
    },
    data: {
      id: 'report--609acc0c-c821-52e0-a6b2-25be0050bbc0',
      spec_version: '2.1',
      type: 'report',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: 'a691be02-fb06-4358-8cf6-a08d97788340',
          type: 'Report',
          created_at: '2024-06-10T12:55:17.446Z',
          updated_at: '2024-07-22T09:21:43.375Z',
          is_inferred: false,
          granted_refs: ['identity--a16d7ba8-5bea-5fe5-9d92-931e20e36727'], // TestOrganization
          creator_ids: ['a93d949b-b56d-4426-b7fe-b79ec3718b0e'],
          workflow_id: 'b28a370a-317b-4c50-8f0d-483b17d11abb'
        }
      },
      created: '2024-06-10T12:55:08.000Z',
      modified: '2024-06-10T12:55:40.833Z',
      revoked: false,
      confidence: 100,
      lang: 'en',
      name: 'test',
      published: '2024-06-10T12:55:08.000Z',
      object_refs: ['attack-pattern--033921be-85df-5f05-8bc0-d3d9fc945db9']
    },
    context: {
      patch: [
        { op: 'add', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs', value: ['identity--a16d7ba8-5bea-5fe5-9d92-931e20e36727'] }
      ],
      reverse_patch: [
        { op: 'remove', path: '/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs' }
      ]
    }
  }
};

const eventWithRelatedRestriction = {
  id: '1733757875310-0',
  event: 'update',
  data: {
    version: '4',
    type: 'update',
    scope: 'external',
    message: 'adds `AlienVault` in `Contains`',
    origin: {
      socket: 'query',
      ip: '::1',
      user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      group_ids: [
        'eeacced8-cf03-4fd3-bfdb-7398839ef015'
      ],
      organization_ids: [],
      user_metadata: {},
      referer: 'http://localhost:3000/dashboard'
    },
    data: {
      id: 'report--50ddc6fe-2a84-5c9a-904d-f964a94d1ff7',
      spec_version: '2.1',
      type: 'report',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'property-extension',
          id: 'e6babfee-aa64-4e3a-9c67-1a163c178ca0',
          type: 'Report',
          created_at: '2024-11-18T09:43:49.623Z',
          updated_at: '2024-12-09T15:24:28.686Z',
          is_inferred: false,
          creator_ids: [
            '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
          ],
          assignee_ids: [
            '71432b4c-34d3-42dc-9b3d-5622b02b4954'
          ],
          workflow_id: 'a4b90e6f-06ae-461a-8dac-666cdb4a5ae7'
        }
      },
      created: '2024-11-18T09:43:40.000Z',
      modified: '2024-12-09T14:18:43.125Z',
      revoked: false,
      confidence: 100,
      lang: 'en',
      object_marking_refs: [
        'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'
      ],
      name: 'Report test',
      description: 'description',
      report_types: [
        'threat-report'
      ],
      published: '2024-11-18T09:43:40.000Z',
      object_refs: [
        'relationship--aefe7518-a66e-5412-a26d-8a5f5eb74fe9',
        'campaign--bce98eb5-25a9-5ba7-b4a0-b160a79d0de7',
        'grouping--a5c0cace-a530-58ae-907f-eb0d8e41913f',
        'threat-actor--fd6b0e6f-96e0-568d-ba24-8a140d0428cd',
        'malware--3b0ff6e4-58fc-5312-aa59-ae755dc10189',
        'intrusion-set--36319194-19e1-50ac-9163-778b56a1bf12',
        'malware--4cc56e92-fc59-500e-966d-bcd32538c248',
        'identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb'
      ]
    },
    context: {
      patch: [
        {
          op: 'add',
          path: '/object_refs/7',
          value: 'identity--e52b2fa3-2af0-5e53-ad38-17d54b3d61cb'
        }
      ],
      reverse_patch: [
        {
          op: 'remove',
          path: '/object_refs/7'
        }
      ],
      relatedRestrictions: {
        markings: [
          '4584aeee-10b6-47a7-808e-603440642285'
        ]
      },
    }
  }
};

describe('History manager test resolveGrantedRefsIds', () => {
  it('should return empty map if granted refs ids are present', async () => {
    const organizationByIdsMap = await resolveGrantedRefsIds(testContext, [eventWithGrantedRefIds]);
    expect(organizationByIdsMap.size).toEqual(0);
  });

  it('should return organization if granted refs are present and not granted refs ids', async () => {
    const organizationByIdsMap = await resolveGrantedRefsIds(testContext, [eventWithGrantedRefsOnly]);
    expect(organizationByIdsMap.size).toEqual(1);
    expect(organizationByIdsMap.has('identity--a16d7ba8-5bea-5fe5-9d92-931e20e36727')).toBeTruthy();
  });
});

describe('history manager test buildHistoryElementsFromEvents', () => {
  it('should build history with granted_refs_ids', async () => {
    const historyElements = await buildHistoryElementsFromEvents(testContext, [eventWithGrantedRefIds]);
    expect(historyElements.length).toEqual(1);
    const historyElement = historyElements[0];
    expect(historyElement.internal_id).toEqual(eventWithGrantedRefIds.id);
    expect(historyElement._index).toEqual(INDEX_HISTORY);
    expect(historyElement.entity_type).toEqual(ENTITY_TYPE_HISTORY);
    expect(historyElement.event_type).toEqual('mutation');
    expect(historyElement.event_scope).toEqual(eventWithGrantedRefIds.event);
    expect(historyElement.user_id).toEqual(eventWithGrantedRefIds.data.origin.user_id);
    expect(historyElement.group_ids).toEqual(eventWithGrantedRefIds.data.origin.group_ids);
    expect(historyElement.organization_ids).toEqual(eventWithGrantedRefIds.data.origin.organization_ids);
    expect(historyElement['rel_granted.internal_id']).toEqual(['c080a677-f640-4643-9d2a-75929ac07b1c', '0c897410-3579-4770-b26e-1fce2e441204']);
  });
  it('should build history with granted_refs ids resolved', async () => {
    const historyElements = await buildHistoryElementsFromEvents(testContext, [eventWithGrantedRefsOnly]);
    expect(historyElements.length).toEqual(1);
    const historyElement = historyElements[0];
    expect(historyElement.internal_id).toEqual(eventWithGrantedRefsOnly.id);
    expect(historyElement._index).toEqual(INDEX_HISTORY);
    expect(historyElement.entity_type).toEqual(ENTITY_TYPE_HISTORY);
    expect(historyElement.event_type).toEqual('mutation');
    expect(historyElement.event_scope).toEqual(eventWithGrantedRefsOnly.event);
    expect(historyElement.user_id).toEqual(eventWithGrantedRefsOnly.data.origin.user_id);
    expect(historyElement.group_ids).toEqual(eventWithGrantedRefsOnly.data.origin.group_ids);
    expect(historyElement.organization_ids).toEqual(eventWithGrantedRefsOnly.data.origin.organization_ids);
    expect(historyElement['rel_granted.internal_id'].length).toEqual(1);
  });
  it('should build history with markins for related entities', async () => {
    const historyElements = await buildHistoryElementsFromEvents(testContext, [eventWithRelatedRestriction]);

    expect(historyElements.length).toEqual(1);
    const historyElement = historyElements[0];
    expect(historyElement.internal_id).toEqual(eventWithRelatedRestriction.id);
    expect(historyElement._index).toEqual(INDEX_HISTORY);
    expect(historyElement.entity_type).toEqual(ENTITY_TYPE_HISTORY);
    expect(historyElement.event_type).toEqual('mutation');
    expect(historyElement.event_scope).toEqual(eventWithRelatedRestriction.event);
    expect(historyElement.user_id).toEqual(eventWithRelatedRestriction.data.origin.user_id);
    expect(historyElement.group_ids).toEqual(eventWithRelatedRestriction.data.origin.group_ids);
    expect(historyElement['rel_object-marking.internal_id'].length).toEqual(2);
  });
});
