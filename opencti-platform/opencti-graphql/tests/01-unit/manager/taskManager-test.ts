import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildContainersElementsBundle, sendResultToQueue } from '../../../src/manager/taskManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { pushToWorkerForConnector } from '../../../src/database/rabbitmq';
import { updateExpectationsNumber } from '../../../src/domain/work';

vi.mock('../../../src/database/rabbitmq', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    pushToWorkerForConnector: vi.fn(),
  };
});

vi.mock('../../../src/domain/work', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    updateExpectationsNumber: vi.fn(),
  };
});

const containers = [{
  _id: '3b753144-0565-448b-b65a-abb333a01979',
  _index: 'opencti_stix_domain_objects-000001',
  base_type: 'ENTITY',
  entity_type: 'Grouping',
  id: '3b753144-0565-448b-b65a-abb333a01979',
  internal_id:
    '3b753144-0565-448b-b65a-abb333a01979',
  standard_id: 'grouping--33a015b6-acb1-563b-8fb7-426bfd9e9a15',
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
  standard_id: 'threat-actor--b84197db-ff53-5167-a6c7-c7cd0fff0277',
};
const expectedIncludedWithNeighborsFieldPatch = [{
  key: 'objects',
  operation: 'add',
  value: [element.id, `${element.id}toId`, `${element.id}rel`],
}];
const expectedWithoutNeighborsFieldPatch = [{
  key: 'objects',
  operation: 'add',
  value: [element.id],
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

describe('TaskManager sendResultToQueue tests', () => {
  const context = testContext;
  const user = ADMIN_USER;
  const task = {
    work_id: 'work-123',
    connector_id: 'connector-456',
    draft_context: null,
  };

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should send each object individually when forceNoSplit is not set', async () => {
    const objects = [
      { id: 'object-1', type: 'indicator' },
      { id: 'object-2', type: 'malware' },
      { id: 'object-3', type: 'report' },
    ];

    await sendResultToQueue(context, user, task, objects);

    // Each object should be sent in its own bundle call
    expect(pushToWorkerForConnector).toHaveBeenCalledTimes(3);

    // Each call should have exactly 1 object in the bundle
    for (let i = 0; i < 3; i += 1) {
      const call = vi.mocked(pushToWorkerForConnector).mock.calls[i];
      expect(call[0]).toBe('connector-456');
      const message = call[1] as { type: string; content: string; work_id: string; no_split: boolean };
      expect(message.type).toBe('bundle');
      expect(message.work_id).toBe('work-123');
      expect(message.no_split).toBe(false);
      const bundle = JSON.parse(Buffer.from(message.content, 'base64').toString('utf-8'));
      expect(bundle.type).toBe('bundle');
      expect(bundle.objects).toHaveLength(1);
      expect(bundle.objects[0].id).toBe(objects[i].id);
    }

    // updateExpectationsNumber should be called for each single-object bundle
    expect(updateExpectationsNumber).toHaveBeenCalledTimes(3);
  });

  it('should send all objects in a single bundle when forceNoSplit is true', async () => {
    const objects = [
      { id: 'object-1', type: 'indicator' },
      { id: 'object-2', type: 'malware' },
      { id: 'object-3', type: 'report' },
    ];

    await sendResultToQueue(context, user, task, objects, { forceNoSplit: true });

    // Only one call to pushToWorkerForConnector
    expect(pushToWorkerForConnector).toHaveBeenCalledTimes(1);

    const call = vi.mocked(pushToWorkerForConnector).mock.calls[0];
    expect(call[0]).toBe('connector-456');
    const message = call[1] as { type: string; content: string; work_id: string; no_split: boolean };
    expect(message.type).toBe('bundle');
    expect(message.work_id).toBe('work-123');
    expect(message.no_split).toBe(true);

    // All objects should be in the single bundle
    const bundle = JSON.parse(Buffer.from(message.content, 'base64').toString('utf-8'));
    expect(bundle.type).toBe('bundle');
    expect(bundle.objects).toHaveLength(3);
    expect(bundle.objects.map((o: { id: string }) => o.id)).toEqual(['object-1', 'object-2', 'object-3']);

    // updateExpectationsNumber should be called once with the total count
    expect(updateExpectationsNumber).toHaveBeenCalledTimes(1);
    expect(updateExpectationsNumber).toHaveBeenCalledWith(context, user, 'work-123', 3);
  });

  it('should not call pushToWorkerForConnector when objects array is empty', async () => {
    await sendResultToQueue(context, user, task, []);

    expect(pushToWorkerForConnector).not.toHaveBeenCalled();
    expect(updateExpectationsNumber).not.toHaveBeenCalled();
  });

  it('should set draft_id from task.draft_context', async () => {
    const taskWithDraft = { ...task, draft_context: 'draft-789' };
    const objects = [{ id: 'object-1', type: 'indicator' }];

    await sendResultToQueue(context, user, taskWithDraft, objects);

    const message = vi.mocked(pushToWorkerForConnector).mock.calls[0][1] as { draft_id: string };
    expect(message.draft_id).toBe('draft-789');
  });

  it('should set draft_id to null when task has no draft_context', async () => {
    const objects = [{ id: 'object-1', type: 'indicator' }];

    await sendResultToQueue(context, user, task, objects);

    const message = vi.mocked(pushToWorkerForConnector).mock.calls[0][1] as { draft_id: string | null };
    expect(message.draft_id).toBeNull();
  });

  it('should set applicant_id to user id', async () => {
    const objects = [{ id: 'object-1', type: 'indicator' }];

    await sendResultToQueue(context, user, task, objects);

    const message = vi.mocked(pushToWorkerForConnector).mock.calls[0][1] as { applicant_id: string };
    expect(message.applicant_id).toBe(user.id);
  });
});
