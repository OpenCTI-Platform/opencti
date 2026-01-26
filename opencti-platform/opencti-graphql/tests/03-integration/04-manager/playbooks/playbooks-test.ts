import { describe, expect, it } from 'vitest';
import { buildStixTaskFromTaskTemplate } from '../../../../src/modules/playbook/playbook-components';
import type { BasicStoreEntityTaskTemplate } from '../../../../src/modules/task/task-template/task-template-types';
import type { StixContainer } from '../../../../src/types/stix-2-1-sdo';

describe('buildStixTaskFromTaskTemplate tests', () => {
  it('should return StixTask from taskTemplate', () => {
    const taskTemplate = {
      _id: '6f9c7686-ec07-4459-bb83-845a8c5eb9b3',
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      creator_id: [
        '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
      ],
      description: '',
      entity_type: 'Task-Template',
      id: '6f9c7686-ec07-4459-bb83-845a8c5eb9b3',
      internal_id: '6f9c7686-ec07-4459-bb83-845a8c5eb9b3',
      name: 'read logs',
      parent_types: [
        'Basic-Object',
        'Internal-Object'
      ],
      'rel_template-task.internal_id': [
        'c4f7df8d-c6a8-418e-a761-536587ec50c1'
      ],
      sort: [
        'task-template--c06283e4-4bc8-59ee-9788-86508394a63e'
      ],
      standard_id: 'task-template--c06283e4-4bc8-59ee-9788-86508394a63e',
      'template-task': 'c4f7df8d-c6a8-418e-a761-536587ec50c1'
    } as unknown as BasicStoreEntityTaskTemplate;

    const container = {
      created: '2025-05-15T09:30:28.035Z',
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'new-sdo',
          id: '0b298142-29e8-4958-8b55-b07af2cb8870',
          type: 'Case-Incident'
        }
      },
      id: 'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167',
      labels: [
        'akira'
      ],
      name: 'incident playbook',
      object_marking_refs: [
        'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
      ],
      object_refs: [
        'incident--e97b1203-fa52-5803-8115-e4144a468189'
      ],
      spec_version: '2.1',
      type: 'case-incident'
    } as unknown as StixContainer;

    const expectedTask = {
      extensions: {
        'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
          extension_type: 'new-sdo',
          id: 'd50ba267-790b-46f6-b5ab-c6ed78389127',
          type: 'Task'
        }
      },
      id: 'task--af7b713a-a10e-5f5e-8a57-7341ab87a2c6',
      name: 'read logs',
      object_marking_refs: [
        'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
      ],
      object_refs: [
        'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167'
      ],
      spec_version: '2.1',
      type: 'task'
    };
    const task = buildStixTaskFromTaskTemplate(taskTemplate, container);
    expect(task.id).toEqual(expectedTask.id);
    expect(task.object_refs).toEqual(expectedTask.object_refs);
    expect(task.object_marking_refs).toEqual(expectedTask.object_marking_refs);
  });
});
