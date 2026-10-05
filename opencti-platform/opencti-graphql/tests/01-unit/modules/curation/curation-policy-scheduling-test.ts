import { describe, expect, it, vi } from 'vitest';
import { findQueuedProposalIds } from '../../../../src/modules/curation/curation-policies';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { ACTION_TYPE_CURATION_APPLY, TASK_TYPE_LIST } from '../../../../src/domain/backgroundTask-common';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../../../../src/schema/internalObject';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(async () => [
    { internal_id: 'policy-task', actions: [{ type: ACTION_TYPE_CURATION_APPLY }], task_ids: ['p1', 'p2'] },
    { internal_id: 'bulk-accept-task', actions: [{ type: ACTION_TYPE_CURATION_APPLY }], task_ids: ['p2', 'p3'] },
    { internal_id: 'other-task', actions: [{ type: 'ADD' }], task_ids: ['p4'] },
    { internal_id: 'task-without-ids', actions: [{ type: ACTION_TYPE_CURATION_APPLY }] },
  ]),
}));

describe('curation policy scheduling', () => {
  it('reads the proposals the incomplete apply tasks hold, whoever queued them', async () => {
    expect([...await findQueuedProposalIds({} as never)].sort()).toEqual(['p1', 'p2', 'p3']);
    const [, , types, opts] = vi.mocked(fullEntitiesList).mock.calls[0] as unknown as [unknown, unknown, string[], { filters: { filters: unknown[] } }];
    expect(types).toEqual([ENTITY_TYPE_BACKGROUND_TASK]);
    // Only the tasks still queued or running hold their proposals.
    expect(opts.filters.filters).toEqual([{ key: ['completed'], values: ['false'] }, { key: ['type'], values: [TASK_TYPE_LIST] }]);
  });
});
