import { beforeEach, describe, expect, it, vi } from 'vitest';
import { elRawGet, elUpdate } from '../../../../src/database/engine';
import { hasProvenanceTriggers, notifyProvenanceChange } from '../../../../src/modules/provenance/provenance-notification';
import { coalesceReassertion, computeAssertedCorroboration, recordUpsertProvenance, writeProvenanceUpdate } from '../../../../src/modules/provenance/provenance-write';
import {
  type AssertionSource,
  MAX_ASSERTIONS_PER_ELEMENT,
  PROVENANCE_SIDE_CHANNEL_FIELDS,
  type StoreAssertion,
  type StoreConflictValue,
} from '../../../../src/modules/provenance/provenance-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const HOUR = 60 * 60 * 1000;
const WINDOW = 24 * HOUR;

vi.mock('../../../../src/modules/provenance/provenance-config', () => ({
  PROVENANCE_ENABLED: true,
  PROVENANCE_REASSERTION_WINDOW_MS: 24 * 60 * 60 * 1000,
  PROVENANCE_DEFAULT_TRACKED_TYPES: ['Malware'],
  PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES: ['uses', 'targets', 'attributed-to'],
}));

vi.mock('../../../../src/modules/entitySetting/entitySetting-utils', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/entitySetting/entitySetting-utils')>(),
  getEntitySettingFromCache: vi.fn(async () => undefined),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elUpdate: vi.fn(),
  elRawGet: vi.fn(),
}));

vi.mock('../../../../src/modules/provenance/provenance-notification', () => ({
  hasProvenanceTriggers: vi.fn(),
  notifyProvenanceChange: vi.fn(),
}));

const SOURCE_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c001';
const OTHER_SOURCE_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c002';
const AT = '2026-10-04T12:00:00.000Z';
const hoursBefore = (hours: number) => new Date(new Date(AT).getTime() - hours * HOUR).toISOString();

const context = { source: 'provenance-reassertion-test' } as AuthContext;
const user = { id: 'c0000000-0000-4000-8000-000000000001', name: '[C] AlienVault' } as AuthUser;
const source: AssertionSource = { source_id: SOURCE_ID, source_kind: 'connector', source_name: 'AlienVault', work_id: null };
const target = { _index: 'opencti_stix_domain_objects-000001', internal_id: 'e0000000-0000-4000-8000-000000000001', entity_type: 'Malware' };

const stored = (sourceId: string, lastAssertedAt: string, firstAssertedAt = '2026-01-01T00:00:00.000Z'): StoreAssertion => ({
  source_id: sourceId,
  source_kind: 'connector',
  source_name: `Source ${sourceId}`,
  first_asserted_at: firstAssertedAt,
  last_asserted_at: lastAssertedAt,
  assert_count: 3,
  confidence: 50,
  work_id: null,
});

const conflictValue = (valueHash: string, sourceId: string, lastAssertedAt: string): StoreConflictValue => ({
  value_hash: valueHash,
  display: valueHash,
  value: `"${valueHash}"`,
  source_id: sourceId,
  source_kind: 'connector',
  source_name: `Source ${sourceId}`,
  confidence: 50,
  last_asserted_at: lastAssertedAt,
});

describe('Provenance re-assertion coalescing', () => {
  it('should not write a source repeating its assertion within the window', () => {
    const element = { x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2))] };
    expect(coalesceReassertion(element, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(true);
  });

  it('should write a new source, an assertion older than the window, or any assertion when the window is disabled', () => {
    const element = { x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2))] };
    expect(coalesceReassertion(element, OTHER_SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion({ x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(25))] }, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion(element, SOURCE_ID, AT, {}, 0).redundant).toEqual(false);
    expect(coalesceReassertion({}, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
  });

  it('should coalesce a counted source beyond the detailed ones on the latest assertion of the element', () => {
    const detailed = Array.from({ length: MAX_ASSERTIONS_PER_ELEMENT }, (_, index) => stored(`b0000000-0000-4000-8000-${String(index).padStart(12, '0')}`, hoursBefore(2)));
    const element = {
      x_opencti_assertions: detailed,
      assertion_source_ids: [...detailed.map(({ source_id }) => source_id), SOURCE_ID],
      last_asserted_at: hoursBefore(2),
    };
    expect(coalesceReassertion(element, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(true);
    // Written once the latest assertion of the element is older than the window, on stale knowledge or with a new conflict
    expect(coalesceReassertion({ ...element, last_asserted_at: hoursBefore(25) }, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion({ ...element, freshness_stale: true }, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion(element, SOURCE_ID, AT, { conflictsAdd: [{ field: 'description', value: conflictValue('h2', SOURCE_ID, AT) }] }, WINDOW).redundant).toEqual(false);
    // A source never counted is always written, and so is a counted source the details still have room for
    expect(coalesceReassertion(element, OTHER_SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion({ ...element, x_opencti_assertions: detailed.slice(1) }, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
  });

  it('should write a re-assertion of stale knowledge to clear its flag', () => {
    const element = { x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2))], freshness_stale: true };
    expect(coalesceReassertion(element, SOURCE_ID, AT, {}, WINDOW).redundant).toEqual(false);
  });

  it('should only keep the conflicting values and removals the element does not already hold', () => {
    const element = {
      x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2))],
      x_opencti_conflicts: [{ field: 'description', values: [conflictValue('h1', SOURCE_ID, hoursBefore(1))] }],
    };
    const repeated = coalesceReassertion(element, SOURCE_ID, AT, { conflictsAdd: [{ field: 'description', value: conflictValue('h1', SOURCE_ID, AT) }] }, WINDOW);
    expect(repeated).toEqual({ redundant: true, conflictsAdd: [], proceduresAdd: [] });
    const fresh = coalesceReassertion(element, SOURCE_ID, AT, { conflictsAdd: [{ field: 'description', value: conflictValue('h2', SOURCE_ID, AT) }] }, WINDOW);
    expect(fresh.redundant).toEqual(false);
    expect(fresh.conflictsAdd.map(({ value }) => value.value_hash)).toEqual(['h2']);
    const otherSource = coalesceReassertion(element, SOURCE_ID, AT, { conflictsAdd: [{ field: 'description', value: conflictValue('h1', OTHER_SOURCE_ID, AT) }] }, WINDOW);
    expect(otherSource.redundant).toEqual(false);
    // The same value proposed by another source is kept as a proposal of its own
    expect(otherSource.conflictsAdd.map(({ value }) => [value.value_hash, value.source_id])).toEqual([['h1', OTHER_SOURCE_ID]]);
    expect(coalesceReassertion(element, SOURCE_ID, AT, { conflictsRemove: [{ field: 'description', value_hash: 'h1' }] }, WINDOW).redundant).toEqual(false);
    expect(coalesceReassertion(element, SOURCE_ID, AT, { conflictsRemove: [{ field: 'description', value_hash: 'h9' }] }, WINDOW).redundant).toEqual(true);
  });

  it('should only keep the procedures the element does not already hold', () => {
    const element = {
      x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2))],
      procedures: [{ text: 'Spearphishing with macros', source_id: SOURCE_ID, last_asserted_at: hoursBefore(1) }],
    };
    const known = { text: '  spearphishing WITH macros ', source_id: SOURCE_ID, last_asserted_at: AT };
    expect(coalesceReassertion(element, SOURCE_ID, AT, { proceduresAdd: [known] }, WINDOW).redundant).toEqual(true);
    const added = { text: 'Drive-by compromise', source_id: SOURCE_ID, last_asserted_at: AT };
    const result = coalesceReassertion(element, SOURCE_ID, AT, { proceduresAdd: [added] }, WINDOW);
    expect(result.redundant).toEqual(false);
    expect(result.proceduresAdd).toEqual([added]);
  });

  it('should keep the same procedure asserted by another source as a new attribution', () => {
    const element = {
      x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(2)), stored(OTHER_SOURCE_ID, hoursBefore(2))],
      procedures: [{ text: 'Spearphishing with macros', source_id: SOURCE_ID, last_asserted_at: hoursBefore(1) }],
    };
    const sameText = { text: 'Spearphishing with macros', source_id: OTHER_SOURCE_ID, last_asserted_at: AT };
    const result = coalesceReassertion(element, OTHER_SOURCE_ID, AT, { proceduresAdd: [sameText] }, WINDOW);
    expect(result.redundant).toEqual(false);
    expect(result.proceduresAdd).toEqual([sameText]);
  });
});

describe('Provenance corroboration read from the update response', () => {
  it('should count a source whose assertion was created by the write', () => {
    const updated = { assertion_source_ids: [OTHER_SOURCE_ID, SOURCE_ID], x_opencti_assertions: [stored(OTHER_SOURCE_ID, hoursBefore(1)), stored(SOURCE_ID, AT, AT)] };
    expect(computeAssertedCorroboration(updated, { assertion_source_ids: [OTHER_SOURCE_ID] }, SOURCE_ID, AT)).toEqual({ from: 1, to: 2 });
  });

  it('should count from the stored state when the loaded element missed a concurrent source', () => {
    const third = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c003';
    const updated = {
      assertion_source_ids: [OTHER_SOURCE_ID, third, SOURCE_ID],
      x_opencti_assertions: [stored(OTHER_SOURCE_ID, hoursBefore(1)), stored(third, hoursBefore(0)), stored(SOURCE_ID, AT, AT)],
    };
    expect(computeAssertedCorroboration(updated, { assertion_source_ids: [OTHER_SOURCE_ID] }, SOURCE_ID, AT)).toEqual({ from: 2, to: 3 });
  });

  it('should not count a source that already asserted the element', () => {
    const updated = { assertion_source_ids: [SOURCE_ID], x_opencti_assertions: [stored(SOURCE_ID, AT)] };
    expect(computeAssertedCorroboration(updated, { assertion_source_ids: [SOURCE_ID] }, SOURCE_ID, AT)).toBeUndefined();
    const evictedDetail = { assertion_source_ids: [SOURCE_ID], x_opencti_assertions: [stored(SOURCE_ID, AT, AT)] };
    expect(computeAssertedCorroboration(evictedDetail, { assertion_source_ids: [SOURCE_ID] }, SOURCE_ID, AT)).toBeUndefined();
  });
});

describe('Provenance upsert recording', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(hasProvenanceTriggers).mockResolvedValue(false);
    vi.mocked(elUpdate).mockResolvedValue({ result: 'updated' } as never);
  });

  it('should not write a redundant re-assertion', async () => {
    const element = { ...target, assertion_source_ids: [SOURCE_ID], x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(1))] };
    const recorded = await recordUpsertProvenance(context, user, element, { source, input: {}, confidence: 50, at: AT });
    expect(recorded?.source).toEqual(source);
    expect(elUpdate).not.toHaveBeenCalled();
    expect(hasProvenanceTriggers).not.toHaveBeenCalled();
  });

  it('should not record anything on a type whose provenance is not tracked', async () => {
    const attackPattern = { ...target, entity_type: 'Attack-Pattern' };
    expect(await recordUpsertProvenance(context, user, attackPattern, { source, input: {}, confidence: 50, at: AT }, { force: true })).toBeNull();
    expect(elUpdate).not.toHaveBeenCalled();
  });

  it('should always write a forced assertion', async () => {
    const element = { ...target, assertion_source_ids: [SOURCE_ID], x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(1))] };
    await recordUpsertProvenance(context, user, element, { source, input: {}, confidence: 50, at: AT }, { force: true });
    expect(elUpdate).toHaveBeenCalledTimes(1);
  });

  it('should notify corroboration from the update response, without any snapshot read', async () => {
    vi.mocked(hasProvenanceTriggers).mockResolvedValue(true);
    vi.mocked(elUpdate).mockResolvedValue({
      result: 'updated',
      get: { _source: { assertion_source_ids: [OTHER_SOURCE_ID, SOURCE_ID], x_opencti_assertions: [stored(OTHER_SOURCE_ID, hoursBefore(1)), stored(SOURCE_ID, AT, AT)] } },
    } as never);
    const element = { ...target, assertion_source_ids: [OTHER_SOURCE_ID], x_opencti_assertions: [stored(OTHER_SOURCE_ID, hoursBefore(1))] };
    await recordUpsertProvenance(context, user, element, { source, input: {}, confidence: 50, at: AT });
    expect(elRawGet).not.toHaveBeenCalled();
    expect(elUpdate).toHaveBeenCalledTimes(1);
    const updateOpts = vi.mocked(elUpdate).mock.calls[0][5];
    expect(updateOpts?.sourceIncludes).toEqual(PROVENANCE_SIDE_CHANNEL_FIELDS);
    expect(notifyProvenanceChange).toHaveBeenCalledWith(
      context,
      element,
      expect.objectContaining({ corroboration: { from: 1, to: 2 } }),
      expect.objectContaining({ assertion_source_ids: [OTHER_SOURCE_ID, SOURCE_ID] }),
    );
  });

  it('should count a conflict value created by a concurrent write only once, re-reading after a version conflict', async () => {
    vi.mocked(hasProvenanceTriggers).mockResolvedValue(false);
    const addition = { field: 'description', value: conflictValue('new-value', SOURCE_ID, AT) };
    // The element was loaded before another write added the same conflict value
    const element = { ...target, x_opencti_assertions: [stored(SOURCE_ID, hoursBefore(48))] };
    vi.mocked(elRawGet)
      .mockResolvedValueOnce({ _seq_no: 7, _primary_term: 1, _source: {} } as never)
      .mockResolvedValueOnce({ _seq_no: 8, _primary_term: 1, _source: { x_opencti_conflicts: [{ field: 'description', values: [addition.value] }] } } as never);
    const versionConflict = { extensions: { data: { cause: { meta: { statusCode: 409 } } } } };
    vi.mocked(elUpdate).mockRejectedValueOnce(versionConflict).mockResolvedValueOnce({ result: 'updated' } as never);
    const { newConflicts } = await writeProvenanceUpdate(context, element, { conflictsAdd: [addition] });
    expect(newConflicts).toEqual([]);
    expect(vi.mocked(elUpdate).mock.calls.map((call) => [call[5]?.ifSeqNo, call[5]?.ifPrimaryTerm])).toEqual([[7, 1], [8, 1]]);
  });

  it('should not report conflict values written without a version after a sustained contention', async () => {
    const addition = { field: 'description', value: conflictValue('new-value', SOURCE_ID, AT) };
    vi.mocked(elRawGet).mockResolvedValue({ _seq_no: 1, _primary_term: 1, _source: {} } as never);
    const versionConflict = { extensions: { data: { cause: { meta: { statusCode: 409 } } } } };
    // Every conditional attempt loses, then the unconditional write lands next to the same value from the winner
    for (let attempt = 0; attempt < 5; attempt += 1) {
      vi.mocked(elUpdate).mockRejectedValueOnce(versionConflict);
    }
    vi.mocked(elUpdate).mockResolvedValueOnce({ result: 'updated', get: { _source: { x_opencti_conflicts: [{ field: 'description', values: [addition.value] }] } } } as never);
    const { newConflicts } = await writeProvenanceUpdate(context, target, { conflictsAdd: [addition] });
    expect(newConflicts).toEqual([]);
    expect(elUpdate).toHaveBeenCalledTimes(6);
    expect(vi.mocked(elUpdate).mock.calls[5][5]?.ifSeqNo).toBeUndefined();
  });

  it('should report the conflict values a write creates, applied on the version it read', async () => {
    const addition = { field: 'description', value: conflictValue('new-value', SOURCE_ID, AT) };
    vi.mocked(elRawGet).mockResolvedValueOnce({ _seq_no: 3, _primary_term: 2, _source: {} } as never);
    vi.mocked(elUpdate).mockResolvedValueOnce({ result: 'updated' } as never);
    const { newConflicts } = await writeProvenanceUpdate(context, target, { conflictsAdd: [addition] });
    expect(newConflicts).toEqual([addition]);
    expect(vi.mocked(elUpdate).mock.calls[0][5]).toMatchObject({ ifSeqNo: 3, ifPrimaryTerm: 2 });
  });
});
