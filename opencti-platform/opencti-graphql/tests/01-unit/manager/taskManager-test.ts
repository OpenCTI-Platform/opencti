import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildContainersElementsBundle } from '../../../src/manager/taskManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const containers = [{
  _id: '3b753144-0565-448b-b65a-abb333a01979',
  _index: 'opencti_stix_domain_objects-000001',
  base_type: 'ENTITY',
  entity_type: 'Grouping',
  id: '3b753144-0565-448b-b65a-abb333a01979',
  internal_id:
    '3b753144-0565-448b-b65a-abb333a01979',
  standard_id: 'grouping--33a015b6-acb1-563b-8fb7-426bfd9e9a15'
}];
const element = {
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
};
const expectedIncludedWithNeighborsFieldPatch = [{
  key: 'objects',
  operation: 'add',
  value: [element.id, `${element.id}toId`, `${element.id}rel`]
}];
const expectedWithoutNeighborsFieldPatch = [{
  key: 'objects',
  operation: 'add',
  value: [element.id]
}];

describe('TaskMananger objectsFromElements tests', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  vi.mock('../../../src/database/middleware-loader', () => {
    return {
      fullRelationsList: vi.fn().mockImplementation((_c, _u, _t, args) => {
        const { callback, fromOrToId } = args;
        const mockRelations = fromOrToId ? fromOrToId.map((id: string) => {
          return { fromId: id, toId: `${id}toId`, id: `${id}rel` };
        }) : [];
        if (callback) {
          callback(mockRelations);
        }
        return mockRelations;
      }),
    };
  });

  it('buildContainersElementsBundle should return object', async () => {
    const objects = await buildContainersElementsBundle(testContext, ADMIN_USER, containers, [element], true, 'ADD');
    expect(objects[0].extensions[STIX_EXT_OCTI].opencti_operation).toEqual('patch');
    expect(objects[0].extensions[STIX_EXT_OCTI].opencti_field_patch).toEqual(expectedIncludedWithNeighborsFieldPatch);

    const objectsWithout = await buildContainersElementsBundle(testContext, ADMIN_USER, containers, [element], false, 'ADD');
    expect(objectsWithout[0].extensions[STIX_EXT_OCTI].opencti_operation).toEqual('patch');
    expect(objectsWithout[0].extensions[STIX_EXT_OCTI].opencti_field_patch).toEqual(expectedWithoutNeighborsFieldPatch);
  });
});
