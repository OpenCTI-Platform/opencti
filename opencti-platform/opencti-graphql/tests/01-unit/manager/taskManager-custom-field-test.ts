import { beforeEach, describe, expect, it, vi } from 'vitest';
import { workerTaskHandler } from '../../../src/manager/taskManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { pushBundleToWorker } from '../../../src/database/rabbitmq';
import { updateProcessedTime } from '../../../src/domain/work';
import { internalFindByIds } from '../../../src/database/middleware-loader';
import { getCustomFieldDefinitions } from '../../../src/modules/customField/custom-field-cache';

vi.mock('../../../src/database/rabbitmq', async (importOriginal) => ({ ...(await importOriginal() as object), pushBundleToWorker: vi.fn() }));
vi.mock('../../../src/domain/work', async (importOriginal) => ({
  ...(await importOriginal() as object),
  updateProcessedTime: vi.fn(),
  updateExpectationsNumber: vi.fn(),
}));
vi.mock('../../../src/domain/backgroundTask', async (importOriginal) => ({ ...(await importOriginal() as object), updateTask: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({ ...(await importOriginal() as object), internalFindByIds: vi.fn() }));
vi.mock('../../../src/modules/customField/custom-field-cache', async (importOriginal) => ({
  ...(await importOriginal() as object),
  getCustomFieldDefinitions: vi.fn(),
}));

const task = { id: 'task-id', type: 'LIST', task_ids: ['element-id'], task_processed_number: 0, work_id: 'work-id', connector_id: 'connector-id' };
const operations = [{ type: 'REPLACE', context: { field: 'x_opencti_cf_note', type: 'ATTRIBUTE', values: ['note'] } }];
const element = (entity_type: string) => ({ id: 'element-id', internal_id: 'element-id', standard_id: 'malware--1', entity_type });

describe('workerTaskHandler with custom fields', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getCustomFieldDefinitions).mockResolvedValue([
      { id: 'cf-note', name: 'x_opencti_cf_note', field_type: 'string', entity_types: ['Case-Incident'] },
    ] as never);
  });

  it('should complete the work of a task whose elements have nothing to apply', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([element('Malware')] as never);
    await workerTaskHandler(testContext, ADMIN_USER, task, 'KNOWLEDGE_CHANGE', operations);
    expect(pushBundleToWorker).not.toHaveBeenCalled();
    expect(updateProcessedTime).toHaveBeenCalledWith(testContext, ADMIN_USER, 'work-id', 'No change to apply');
  });

  it('should leave the work to the workers when a change is queued', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([element('Case-Incident')] as never);
    await workerTaskHandler(testContext, ADMIN_USER, task, 'KNOWLEDGE_CHANGE', operations);
    expect(pushBundleToWorker).toHaveBeenCalledTimes(1);
    expect(updateProcessedTime).not.toHaveBeenCalled();
  });
});
