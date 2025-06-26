import { afterEach, describe, expect, it, vi } from 'vitest';
import { objectsFromElements } from '../../../src/manager/taskManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { StoreProxyRelation } from '../../../src/types/store';
import type { BasicStoreEntityManagerConfiguration } from '../../../src/modules/managerConfiguration/managerConfiguration-types';

const containers = [{ _id: '3b753144-0565-448b-b65a-abb333a01979',
  _index: 'opencti_stix_domain_objects-000001',
  base_type: 'ENTITY',
  entity_type: 'Grouping',
  id: '3b753144-0565-448b-b65a-abb333a01979',
  internal_id:
    '3b753144-0565-448b-b65a-abb333a01979',
  sort: [1750854201251],
  standard_id: 'grouping--33a015b6-acb1-563b-8fb7-426bfd9e9a15' }];
const elements = [{
  _id: '41107f85-f2dc-4422-b615-c12e8ea67aec',
  _index: 'opencti_stix_domain_objects-000001',
  base_type: 'ENTITY',
  entity_type: 'Threat-Actor-Individual',
  first_seen: '1970-01-01T00:00:00.000Z',
  id: '41107f85-f2dc-4422-b615-c12e8ea67aec',
  internal_id: '41107f85-f2dc-4422-b615-c12e8ea67aec',
  last_seen: '5138-11-16T09:46:40.000Z',
  sort: [1749547966450],
  standard_id: 'threat-actor--b84197db-ff53-5167-a6c7-c7cd0fff0277'
}];
const expectedObjects = [{
  extensions: {
    'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
      id: '3b753144-0565-448b-b65a-abb333a01979',
      type: 'Grouping'
    }
  },
  id: 'grouping--33a015b6-acb1-563b-8fb7-426bfd9e9a15',
  object_refs: ['threat-actor--b84197db-ff53-5167-a6c7-c7cd0fff0277'],
  opencti_field_patch: [{
    key: 'objects',
    operation: 'add',
    value: ['41107f85-f2dc-4422-b615-c12e8ea67aec', 'ab63a7fd-5660-44b9-afd9-45aef583684d', '4f4109aa-eb21-4050-94cd-20f38f8b501a'] }],
  opencti_operation: 'patch',
  type: 'grouping' }];

// const allRelations = [];

describe('TaskMananger objectsFromElements tests', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  vi.mock('../../../src/manager/taskManager', () => {
    return {
      objectsFromElements: vi.fn().mockImplementation(() => {
        const listAllRelations = [];
        return listAllRelations;
      }),
    };
  });

  it('objectsFromElements should return object', async () => {
    const objects = await objectsFromElements(testContext, ADMIN_USER, containers, elements, true, 'ADD');
    expect(objects).toEqual(expectedObjects);
  });
});
