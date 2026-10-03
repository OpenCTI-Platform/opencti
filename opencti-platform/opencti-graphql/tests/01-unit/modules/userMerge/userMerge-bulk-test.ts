import { beforeEach, describe, expect, it, vi } from 'vitest';

const elRawUpdateByQuery = vi.fn();
const elRawSearch = vi.fn();
const elBulk = vi.fn();
vi.mock('../../../../src/database/engine', () => ({
  elRawUpdateByQuery: (query: unknown) => elRawUpdateByQuery(query),
  elRawSearch: (context: unknown, user: unknown, scope: unknown, args: unknown) => elRawSearch(context, user, scope, args),
  elBulk: (context: unknown, args: unknown) => elBulk(context, args),
}));

const { userMergeBulkRewrite, userMergeBulkUpdate, userMergeScanForRewrite } = await import('../../../../src/modules/userMerge/userMerge-bulk');

const context = {} as never;

describe('User merge bulk update', () => {
  beforeEach(() => {
    elRawUpdateByQuery.mockReset();
  });

  it('should surface the counters of a clean update', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 10, total: 10, failures: [], version_conflicts: 0 });
    const result = await userMergeBulkUpdate('label', ['index'], { query: {} });
    expect(result).toEqual({ updated: 10, total: 10, failures: [], version_conflicts: 0 });
  });

  it('should fail on a version conflict instead of reporting success', async () => {
    // The exact shape elOperationForMigration reports as a success today.
    elRawUpdateByQuery.mockResolvedValue({ updated: 3000, total: 10000, failures: [], version_conflicts: 7000 });
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('failures or version conflicts');
  });

  it('should fail on a non-empty failure list', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 9, total: 10, failures: [{ reason: 'mapping' }], version_conflicts: 0 });
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('failures or version conflicts');
  });

  it('should never let the engine skip conflicting documents', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 1, total: 1, failures: [], version_conflicts: 0 });
    await userMergeBulkUpdate('label', ['index'], { query: {} });
    const [query] = elRawUpdateByQuery.mock.calls[0];
    expect(query.conflicts).toBe('abort');
    expect(query.wait_for_completion).toBe(true);
    expect(query.refresh).toBe(true);
  });

  it('should wrap a raw engine error', async () => {
    elRawUpdateByQuery.mockRejectedValue(new Error('connection reset'));
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('User merge bulk update failed');
  });

  it('should treat missing counters as zero rather than as absent', async () => {
    elRawUpdateByQuery.mockResolvedValue({});
    const result = await userMergeBulkUpdate('label', ['index'], { query: {} });
    expect(result).toEqual({ updated: 0, total: 0, failures: [], version_conflicts: 0 });
  });
});

const hit = (id: string, index = 'opencti_internal_objects') => ({
  _id: `${index}/${id}`,
  _index: index,
  _source: { internal_id: id },
  sort: [id, index],
});

describe('User merge rewrite scan', () => {
  beforeEach(() => {
    elRawSearch.mockReset();
  });

  it('should return what one page holds, in the index it was read from', async () => {
    elRawSearch.mockResolvedValue({ hits: { hits: [hit('a')] } });
    const candidates = await userMergeScanForRewrite(context, ['index'], { bool: {} });
    expect(candidates).toEqual([{ id: 'opencti_internal_objects/a', index: 'opencti_internal_objects', source: { internal_id: 'a' } }]);
  });

  // The scan has to survive a target holding more documents than one page, and the platform's
  // result window is what rules out paging on from/size.
  it('should ask for the next page from the last document of a full one', async () => {
    elRawSearch
      .mockImplementationOnce((_c: unknown, _u: unknown, _s: unknown, args: any) => Promise.resolve({
        hits: { hits: Array.from({ length: args.size }, (_, index) => hit(`first-${index}`)) },
      }))
      .mockResolvedValueOnce({ hits: { hits: [hit('last')] } });
    const candidates = await userMergeScanForRewrite(context, ['index'], { bool: {} });
    const [, second] = elRawSearch.mock.calls;
    expect(second[3].body.search_after).toEqual([`first-${second[3].size - 1}`, 'opencti_internal_objects']);
    expect(candidates[candidates.length - 1].id).toEqual('opencti_internal_objects/last');
  });

  it('should break a tie on the index, so no copy sharing an internal id is paged over', async () => {
    elRawSearch.mockResolvedValue({ hits: { hits: [] } });
    await userMergeScanForRewrite(context, ['index'], { bool: {} });
    expect(elRawSearch.mock.calls[0][3].body.sort).toEqual([{ 'internal_id.keyword': 'asc' }, { _index: 'asc' }]);
  });

  // A draft copy is a reindex that keeps the internal id of the document it copies, so the live
  // document and its draft are ex aequo on the primary sort key. The engine is stubbed with the
  // rule that matters here — search_after is strictly greater than the key it is given — because
  // paging on the internal id alone drops whichever copy falls after a boundary, and that is how
  // the safety net could sweep a document without ever seeing it.
  it('should carry over a copy that shares an internal id across a page boundary', async () => {
    // Built from the page size the scan asks for, ordered as the composite sort key orders them,
    // so the two copies of `shared` straddle the boundary of a full first page.
    let documents: { id: string; index: string }[] = [];
    elRawSearch.mockImplementation((_c: unknown, _u: unknown, _s: unknown, args: any) => {
      if (documents.length === 0) {
        documents = [
          ...Array.from({ length: args.size - 1 }, (_, index) => ({
            id: `doc-${String(index).padStart(6, '0')}`,
            index: 'opencti_internal_objects',
          })),
          { id: 'shared', index: 'opencti_draft_objects' },
          { id: 'shared', index: 'opencti_internal_objects' },
        ];
      }
      const keys = args.body.sort.map((entry: Record<string, string>) => Object.keys(entry)[0]);
      const keyOf = (document: { id: string; index: string }) => keys
        .map((key: string) => (key === '_index' ? document.index : document.id));
      const after = args.body.search_after;
      const isAfter = (key: string[]) => {
        if (!after) {
          return true;
        }
        for (let i = 0; i < key.length; i += 1) {
          if (key[i] !== after[i]) {
            return key[i] > after[i];
          }
        }
        return false;
      };
      const selected = documents
        .map((document) => ({ document, key: keyOf(document) }))
        .filter((entry) => isAfter(entry.key))
        .slice(0, args.size);
      return Promise.resolve({
        hits: {
          hits: selected.map((entry) => ({
            _id: `${entry.document.index}/${entry.document.id}`,
            _index: entry.document.index,
            _source: { internal_id: entry.document.id },
            sort: entry.key,
          })),
        },
      });
    });
    const candidates = await userMergeScanForRewrite(context, ['index'], { bool: {} });
    expect(candidates.filter((candidate) => candidate.source.internal_id === 'shared')).toHaveLength(2);
    expect(candidates).toHaveLength(documents.length);
  });

  it('should wrap a raw engine error', async () => {
    elRawSearch.mockRejectedValue(new Error('connection reset'));
    await expect(userMergeScanForRewrite(context, ['index'], { bool: {} })).rejects.toThrow('User merge rewrite scan failed');
  });
});

describe('User merge bulk rewrite', () => {
  beforeEach(() => {
    elBulk.mockReset();
  });

  it('should not reach the engine when there is nothing to write', async () => {
    expect(await userMergeBulkRewrite(context, 'label', [])).toEqual(0);
    expect(elBulk).not.toHaveBeenCalled();
  });

  // Partial documents: a merge rewrites one field and must not resurrect the rest of a document
  // read a moment earlier.
  it('should write each document back as a partial update in its own index', async () => {
    elBulk.mockResolvedValue({});
    const updated = await userMergeBulkRewrite(context, 'label', [
      { id: 'a', index: 'index-one', doc: { filters: 'rewritten' } },
      { id: 'b', index: 'index-two', doc: { filters: 'rewritten' } },
    ]);
    expect(updated).toEqual(2);
    expect(elBulk.mock.calls[0][1].body).toEqual([
      { update: { _index: 'index-one', _id: 'a' } },
      { doc: { filters: 'rewritten' } },
      { update: { _index: 'index-two', _id: 'b' } },
      { doc: { filters: 'rewritten' } },
    ]);
  });

  it('should wrap a raw engine error', async () => {
    elBulk.mockRejectedValue(new Error('connection reset'));
    const updates = [{ id: 'a', index: 'index-one', doc: {} }];
    await expect(userMergeBulkRewrite(context, 'label', updates)).rejects.toThrow('User merge bulk rewrite failed');
  });
});
