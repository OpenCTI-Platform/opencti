import type { StoreEntityTask } from '../../../../../../src/modules/task/task-types';

export const TASK_INSTANCE = {
  id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  standard_id: 'task--8788511e-974c-571d-9a47-381299785038',
  entity_type: 'Task',
  name: 'task STIX 2.0',
  description: 'Description',
  created: '2025-06-26T17:55:28.987Z',
  modified: '2025-07-02T15:46:34.373Z',
  confidence: 100,
  revoked: false,
  due_date: '2025-06-27T22:00:00.000Z',
  x_opencti_files: [
    {
      file_markings: [],
      mime_type: 'application/json',
      name: 'ipv4_example.json',
      id: 'import/Task/d4e02a21-0dda-4295-be80-3c81503b69c8/ipv4_example.json',
      version: '2025-07-02T15:47:23.032Z',
    },
  ],
  objectAssignee: [
    {
      internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      standard_id: 'user--12ea8141-dc6d-5031-9a1b-c28aeac7198b',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'admin',
    },
  ],
  objectOrganization: [
    {
      standard_id: 'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
      entity_type: 'Organization',
      name: 'Filigran',
    },
  ],
  objectMarking: [{ standard_id: 'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34' }],
  objectLabel: [{ value: 'ryuk' }],
  objectParticipant: [
    {
      internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
      standard_id: 'user--12ea8141-dc6d-5031-9a1b-c28aeac7198b',
      entity_type: 'User',
      base_type: 'ENTITY',
      name: 'admin',
    },
  ],
  objects: [{ standard_id: 'case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763' }],
} as unknown as StoreEntityTask;

export const EXPECTED_TASK = {
  id: 'x-opencti-task--8788511e-974c-571d-9a47-381299785038',
  spec_version: '2.0',
  revoked: false,
  confidence: 100,
  created: '2025-06-26T17:55:28.987Z',
  modified: '2025-07-02T15:46:34.373Z',
  name: 'task STIX 2.0',
  description: 'Description',
  due_date: '2025-06-27T22:00:00.000Z',
  labels: [
    'ryuk',
  ],
  x_opencti_id: 'd4e02a21-0dda-4295-be80-3c81503b69c8',
  x_opencti_type: 'Task',
  type: 'x-opencti-task',
  object_marking_refs: [
    'marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34',
  ],
  object_refs: [
    'case-rft--8456f0c2-0308-578b-b90c-1dd6e0440763',
  ],
  created_by_ref: undefined,
  x_opencti_files: [{
    mime_type: 'application/json',
    name: 'ipv4_example.json',
    object_marking_refs: [],
    uri: '/storage/get/import/Task/d4e02a21-0dda-4295-be80-3c81503b69c8/ipv4_example.json',
    version: '2025-07-02T15:47:23.032Z',
  }],
  external_references: [],
  x_opencti_granted_refs: [
    'identity--8cb00c79-ab20-5ed4-b37d-337241b96a29',
  ],
};
