import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { curationMergeRecorder } from '../../../../src/modules/curation/curation-merge-record';
import { patchAttribute } from '../../../../src/database/middleware';
import { addCurationMergeRecordCount } from '../../../../src/manager/telemetryManager';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { StoreObject } from '../../../../src/types/store';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(async () => ({ element: {} })),
}));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCurationMergeRecordCount: vi.fn(async () => undefined),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id' } as AuthUser;
const MOVED = 'import/Malware/target-id/report.pdf';
const preparation = {
  recordId: 'record-id',
  target: { internal_id: 'target-id', standard_id: 'malware--target', entity_type: 'Malware', name: 'Target', attributes: {}, refs: {} },
  sources: [{
    internal_id: 'source-id',
    standard_id: 'malware--source',
    entity_type: 'Malware',
    name: 'Source',
    attributes: {},
    refs: {},
    redirected: [],
    recreatable: [],
    moved_file_ids: [MOVED],
    contributed_aliases: [],
    contributed_stix_ids: [],
    reverted_at: null,
  }],
  irreversibleReason: null,
};
const mergedInstance = { internal_id: 'target-id', standard_id: 'malware--target', entity_type: 'Malware', name: 'Target' } as unknown as StoreObject;
const mergedSource = (fileIds: string[]) => ({
  internal_id: 'source-id',
  entity_type: 'Malware',
  x_opencti_files: fileIds.map((id) => ({ id, name: id.split('/').pop() })),
}) as unknown as StoreObject;
const recordPatch = () => vi.mocked(patchAttribute).mock.calls.find((args) => args[2] === 'record-id')?.[4] as Record<string, unknown>;

describe('curation merge record of the merged files', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('records the merge as reversible when every file planned to move is under the merged entity', async () => {
    await curationMergeRecorder.commit(context, user, preparation as never, { mergedInstance, sources: [mergedSource([MOVED])] } as never);
    expect(recordPatch()).toMatchObject({ merge_status: 'active', irreversible_reason: null });
    expect(addCurationMergeRecordCount).toHaveBeenCalled();
  });

  it('records the merge as not reversible when a file could not be moved, the merge deleting it with its entity', async () => {
    await curationMergeRecorder.commit(context, user, preparation as never, { mergedInstance, sources: [mergedSource([])] } as never);
    expect(recordPatch()).toMatchObject({ merge_status: 'irreversible', irreversible_reason: 'file_not_moved' });
    expect(addCurationMergeRecordCount).not.toHaveBeenCalled();
  });
});
