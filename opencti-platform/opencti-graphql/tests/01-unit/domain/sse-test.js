import { computeEventsDiff, isInstanceMatchFilters } from '../../../src/graphql/sseMiddleware';
import { buildStixData } from '../../../src/database/stix';
import { rebuildInstanceBeforePatch } from '../../../src/utils/patch';

const testEvents = [
  {
    id: '1619436072266-0',
    topic: 'update',
    data: {
      markings: ['marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/f499ceab-b3bf-4f39-827d-aea43beed391',
      },
      data: {
        threat_actor_types: ['competitor'],
        spec_version: '2.1',
        created: '2021-04-26T11:20:53.686Z',
        confidence: 15,
        description: 'TEST',
        created_at: '2021-04-26T11:20:53.686Z',
        revoked: false,
        updated_at: '2021-04-26T11:20:53.686Z',
        name: 'SSE TEST',
        modified: '2021-04-26T11:20:53.686Z',
        id: 'threat-actor--b3486bf4-2cf8-527c-ab40-3fd2ff54de77',
        lang: 'en',
        x_opencti_patch: {
          add: {
            object_marking_refs: [
              {
                value: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
                x_opencti_internal_id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
              },
            ],
          },
        },
        x_opencti_id: 'f499ceab-b3bf-4f39-827d-aea43beed391',
        type: 'threat-actor',
        object_marking_refs: [
          'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
          'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
        ],
      },
      message: 'adds the `object_marking_refs` value `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da`',
      version: '2',
    },
  },
  {
    id: '1619436079034-0',
    topic: 'update',
    data: {
      markings: [],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/f499ceab-b3bf-4f39-827d-aea43beed391',
      },
      data: {
        x_opencti_patch: {
          replace: { threat_actor_types: { current: ['competitor', 'crime-syndicate'], previous: ['competitor'] } },
        },
        id: 'threat-actor--b3486bf4-2cf8-527c-ab40-3fd2ff54de77',
        x_opencti_id: 'f499ceab-b3bf-4f39-827d-aea43beed391',
        type: 'threat-actor',
      },
      message: 'replaces the `threat_actor_types` by `current: competitor,crime-syndicate, previous: competitor`',
      version: '2',
    },
  },
  {
    id: '1619436098591-0',
    topic: 'create',
    data: {
      markings: [],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/f499ceab-b3bf-4f39-827d-aea43beed391',
      },
      data: {
        name: 'JULIEN',
        description: '',
        identity_class: 'individual',
        id: 'identity--d969b177-497f-598d-8428-b128c8f5f819',
        x_opencti_id: '3ae87124-b240-42b7-b309-89d8eb66e9cc',
        type: 'identity',
      },
      message: 'creates a Individual `JULIEN`',
      version: '2',
    },
  },
  {
    id: '1619436098812-0',
    topic: 'update',
    data: {
      markings: [
        'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
      ],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/f499ceab-b3bf-4f39-827d-aea43beed391',
      },
      data: {
        x_opencti_patch: {
          add: {
            created_by_ref: [
              {
                value: 'identity--d969b177-497f-598d-8428-b128c8f5f819',
                x_opencti_internal_id: '3ae87124-b240-42b7-b309-89d8eb66e9cc',
              },
            ],
          },
        },
        id: 'threat-actor--b3486bf4-2cf8-527c-ab40-3fd2ff54de77',
        x_opencti_id: 'f499ceab-b3bf-4f39-827d-aea43beed391',
        type: 'threat-actor',
      },
      message: 'adds the `created_by_ref` value `identity--d969b177-497f-598d-8428-b128c8f5f819`',
      version: '2',
    },
  },
  {
    id: '1619436177718-0',
    topic: 'update',
    data: {
      markings: [
        'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
      ],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/f499ceab-b3bf-4f39-827d-aea43beed391',
      },
      data: {
        x_opencti_patch: {
          remove: {
            created_by_ref: [
              {
                value: 'identity--d969b177-497f-598d-8428-b128c8f5f819',
                x_opencti_internal_id: '3ae87124-b240-42b7-b309-89d8eb66e9cc',
              },
            ],
          },
        },
        id: 'threat-actor--b3486bf4-2cf8-527c-ab40-3fd2ff54de77',
        x_opencti_id: 'f499ceab-b3bf-4f39-827d-aea43beed391',
        type: 'threat-actor',
      },
      message: 'removes the `created_by_ref` value `identity--d969b177-497f-598d-8428-b128c8f5f819`',
      version: '2',
    },
  },
  {
    id: '1619436223973-0',
    topic: 'create',
    data: {
      markings: [],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors?',
      },
      data: {
        name: 'SSE DELETE',
        description: 'XXXXXX',
        threat_actor_types: ['hacker'],
        confidence: 15,
        id: 'threat-actor--df75d034-c158-5a36-81f3-034aa9ce5eaa',
        x_opencti_id: 'e3ae5740-b8c1-451c-bac7-3399d1e0b42e',
        type: 'threat-actor',
      },
      message: 'creates a Threat-Actor `SSE DELETE`',
      version: '2',
    },
  },
  {
    id: '1619436232919-0',
    topic: 'update',
    data: {
      markings: [],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/e3ae5740-b8c1-451c-bac7-3399d1e0b42e',
      },
      data: {
        x_opencti_patch: { replace: { description: { current: 'XXXXXX YYYYYYY', previous: 'XXXXXX' } } },
        id: 'threat-actor--df75d034-c158-5a36-81f3-034aa9ce5eaa',
        x_opencti_id: 'e3ae5740-b8c1-451c-bac7-3399d1e0b42e',
        type: 'threat-actor',
      },
      message: 'replaces the `description` by `current: XXXXXX YYYYYYY, previous: XXXXXX`',
      version: '2',
    },
  },
  {
    id: '1619436240680-0',
    topic: 'delete',
    data: {
      markings: [],
      origin: {
        ip: '::1',
        user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        referer: 'http://localhost:4000/dashboard/threats/threat_actors/e3ae5740-b8c1-451c-bac7-3399d1e0b42e',
      },
      data: {
        threat_actor_types: ['hacker'],
        spec_version: '2.1',
        created: '2021-04-26T11:23:44.858Z',
        confidence: 15,
        description: 'XXXXXX YYYYYYY',
        created_at: '2021-04-26T11:23:44.858Z',
        revoked: false,
        updated_at: '2021-04-26T11:23:53.791Z',
        name: 'SSE DELETE',
        modified: '2021-04-26T11:23:53.791Z',
        id: 'threat-actor--df75d034-c158-5a36-81f3-034aa9ce5eaa',
        lang: 'en',
        x_opencti_id: 'e3ae5740-b8c1-451c-bac7-3399d1e0b42e',
        type: 'threat-actor',
      },
      message: 'deletes a Threat-Actor `SSE DELETE`',
      version: '2',
    },
  },
];

test('Should compute events differential', () => {
  const elements = computeEventsDiff(testEvents);
  const ids = elements.map((e) => e.id);
  expect(ids).toEqual([
    'threat-actor--b3486bf4-2cf8-527c-ab40-3fd2ff54de77',
    'identity--d969b177-497f-598d-8428-b128c8f5f819',
  ]);
});

const instance = {
  standard_id: 'threat-actor--214c643d-8ad5-5911-a08e-7aa9111ff8b6',
  personal_motivations: ['coercion'],
  threat_actor_types: ['crime-syndicate', "criminal'"],
  i_created_at_day: '2021-04-23',
  spec_version: '2.1',
  parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  internal_id: 'b397cb7e-1884-4809-ab12-3434931201b7',
  created: '2021-04-23T22:44:44.554Z',
  i_created_at_month: '2021-04',
  confidence: 85,
  description: 'asd awd wadwa',
  created_at: '2021-04-23T22:44:44.554Z',
  revoked: false,
  i_created_at_year: '2021',
  base_type: 'ENTITY',
  entity_type: 'Threat-Actor',
  updated_at: '2021-04-26T18:52:45.914Z',
  name: 'd adsad sadas d',
  modified: '2021-04-26T18:52:45.914Z',
  i_aliases_ids: ['aliases--bec8cf6d-24b2-5953-b861-6c26f01564bd'],
  id: 'b397cb7e-1884-4809-ab12-3434931201b7',
  lang: 'en',
  x_opencti_stix_ids: [],
  _index: 'opencti_stix_domain_objects-000001',
  objectMarking: [
    {
      standard_id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
      x_opencti_color: '#c62828',
      x_opencti_order: 4,
      i_created_at_day: '2021-04-08',
      internal_id: '5b14d970-2153-4304-9af3-06d574fa778b',
      spec_version: '2.1',
      parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Meta-Object'],
      definition_type: 'TLP',
      created: '2021-04-08T19:10:55.331Z',
      i_created_at_month: '2021-04',
      created_at: '2021-04-08T19:10:55.331Z',
      i_created_at_year: '2021',
      entity_type: 'Marking-Definition',
      base_type: 'ENTITY',
      updated_at: '2021-04-08T19:10:55.331Z',
      modified: '2021-04-08T19:10:55.331Z',
      definition: 'TLP:RED',
      id: '5b14d970-2153-4304-9af3-06d574fa778b',
      x_opencti_stix_ids: ['marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'],
      _index: 'opencti_stix_meta_objects-000001',
    },
    {
      standard_id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
      x_opencti_color: '#2e7d32',
      x_opencti_order: 2,
      i_created_at_day: '2021-04-08',
      internal_id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
      spec_version: '2.1',
      parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Meta-Object'],
      definition_type: 'TLP',
      created: '2021-04-08T19:10:55.236Z',
      i_created_at_month: '2021-04',
      created_at: '2021-04-08T19:10:55.236Z',
      i_created_at_year: '2021',
      entity_type: 'Marking-Definition',
      base_type: 'ENTITY',
      updated_at: '2021-04-08T19:10:55.236Z',
      modified: '2021-04-08T19:10:55.236Z',
      definition: 'TLP:GREEN',
      id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
      x_opencti_stix_ids: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'],
      _index: 'opencti_stix_meta_objects-000001',
    },
  ],
  objectLabel: [
    {
      standard_id: 'label--e1248458-93dc-5e37-b9e6-ba4192eafe4c',
      i_created_at_day: '2021-04-12',
      color: '#c25555',
      internal_id: '884506e4-ad4a-49cd-88bc-d40b7069f496',
      spec_version: '2.1',
      parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Meta-Object'],
      created: '2021-04-12T19:51:13.677Z',
      i_created_at_month: '2021-04',
      created_at: '2021-04-12T19:51:13.677Z',
      i_created_at_year: '2021',
      entity_type: 'Label',
      base_type: 'ENTITY',
      updated_at: '2021-04-12T19:51:13.677Z',
      modified: '2021-04-12T19:51:13.677Z',
      id: '884506e4-ad4a-49cd-88bc-d40b7069f496',
      x_opencti_stix_ids: [],
      value: 'label',
      _index: 'opencti_stix_meta_objects-000001',
    },
  ],
  createdBy: [
    {
      standard_id: 'identity--73adbcdc-176e-5b23-8a8e-8fc1368bad96',
      identity_class: 'individual',
      i_created_at_day: '2021-04-26',
      internal_id: 'b2e2a15f-b1a5-4017-bfeb-3238ce4fbe86',
      spec_version: '2.1',
      parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
      created: '2021-04-26T11:55:29.695Z',
      i_created_at_month: '2021-04',
      confidence: 15,
      description: 'SA',
      created_at: '2021-04-26T11:55:29.695Z',
      revoked: false,
      i_created_at_year: '2021',
      entity_type: 'Individual',
      base_type: 'ENTITY',
      updated_at: '2021-04-26T11:55:29.695Z',
      name: 'SAM',
      modified: '2021-04-26T11:55:29.695Z',
      i_aliases_ids: ['aliases--31213d6b-aa46-5f0a-a748-d47478ccaab0'],
      id: 'b2e2a15f-b1a5-4017-bfeb-3238ce4fbe86',
      x_opencti_stix_ids: [],
      lang: 'en',
      _index: 'opencti_stix_domain_objects-000001',
    },
  ],
};
const patch = {
  replace: {
    confidence: {
      current: 85,
      previous: 75,
    },
  },
  add: {
    object_marking_refs: [
      {
        value: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        x_opencti_internal_id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
      },
    ],
  },
};
test('Should rebuild instance', () => {
  const data = buildStixData(instance, { patchGeneration: true });
  const rebuildInstance = rebuildInstanceBeforePatch(data, patch);
  expect(rebuildInstance.confidence).toEqual(75);
  expect(rebuildInstance.object_marking_refs.length).toEqual(1);
});

const filters = {
  createdBy: [
    {
      id: 'b2e2a15f-b1a5-4017-bfeb-3238ce4fbe86',
      value: 'ORGA',
    },
  ],
  entity_type: [
    {
      id: 'Threat-Actor',
      value: 'Threat Actor',
    },
  ],
  labelledBy: [
    {
      id: '884506e4-ad4a-49cd-88bc-d40b7069f496',
      value: 'label',
    },
  ],
  markedBy: [
    {
      id: '6bf6c4e3-20f0-4497-bb08-bd2cf59b1e84',
      value: 'TLP:GREEN',
    },
  ],
};

test('Should instance filtered', () => {
  const basicInstance = buildStixData(instance, { patchGeneration: true });
  const initialInstance = rebuildInstanceBeforePatch(basicInstance, patch);
  const isInitialInterest = isInstanceMatchFilters(initialInstance, filters);
  const isUpdatedInterest = isInstanceMatchFilters(basicInstance, filters);
  expect(isInitialInterest).toBeFalsy();
  expect(isUpdatedInterest).toBeTruthy();
});
