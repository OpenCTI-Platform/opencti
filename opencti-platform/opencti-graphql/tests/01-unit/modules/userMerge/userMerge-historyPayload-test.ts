import { describe, expect, it } from 'vitest';
import { userMergeRewriteHistoryChanges } from '../../../../src/modules/userMerge/userMerge-historyPayloadHandler';

const SOURCE = '11111111-1111-4111-8111-111111111111';
const TARGET = '22222222-2222-4222-8222-222222222222';
const OTHER = '33333333-3333-4333-8333-333333333333';

// The shape the history manager writes: one entry per changed field, each value keeping the id it
// resolved and the label map it resolved to.
const change = (field: string, added: { raw: string; translated?: string }[], removed: { raw: string; translated?: string }[] = []) => ({
  field,
  changes_added: added,
  changes_removed: removed,
});
const labelOf = (id: string, name: string) => JSON.stringify({ [id]: name });

describe('history recorded changes rewriting', () => {
  it('should leave changes naming neither account untouched', () => {
    expect(userMergeRewriteHistoryChanges([change('Report--objectAssignee', [{ raw: OTHER, translated: labelOf(OTHER, 'other') }])], SOURCE, TARGET)).toBeNull();
  });

  it('should ignore a record without recorded changes', () => {
    expect(userMergeRewriteHistoryChanges(undefined, SOURCE, TARGET)).toBeNull();
  });

  // The platform resolves `raw` into a name when the history is read: left on the source, it reads
  // "Restricted" once the source account is deleted.
  it('should rewrite the id a change resolves, on both sides', () => {
    const rewritten = userMergeRewriteHistoryChanges([change('Report--creator_id', [{ raw: SOURCE }], [{ raw: SOURCE }])], SOURCE, TARGET) as any[];
    expect(rewritten[0].changes_added[0].raw).toEqual(TARGET);
    expect(rewritten[0].changes_removed[0].raw).toEqual(TARGET);
  });

  it('should rewrite the id a change carries as a label map key, and keep the recorded name', () => {
    const rewritten = userMergeRewriteHistoryChanges([change('Report--objectAssignee', [{ raw: SOURCE, translated: labelOf(SOURCE, 'source user') }])], SOURCE, TARGET) as any[];
    expect(rewritten[0].changes_added[0].raw).toEqual(TARGET);
    expect(JSON.parse(rewritten[0].changes_added[0].translated)).toEqual({ [TARGET]: 'source user' });
  });

  // An object attribute records its value serialized in `raw`, such as the authorized members.
  it('should reach the id inside a serialized object value', () => {
    const members = (id: string) => JSON.stringify([{ id, access_right: 'view' }]);
    const rewritten = userMergeRewriteHistoryChanges([change('Report--authorized_members', [{ raw: members(SOURCE) }])], SOURCE, TARGET) as any[];
    expect(rewritten[0].changes_added[0].raw).toEqual(members(TARGET));
  });

  // Editing a filter field records the new filters serialized in `raw`.
  it('should reach the id inside serialized filters', () => {
    const filters = (id: string) => JSON.stringify({ mode: 'and', filters: [{ key: ['creator_id'], values: [id] }], filterGroups: [] });
    const rewritten = userMergeRewriteHistoryChanges([change('Trigger--filters', [{ raw: filters(SOURCE) }])], SOURCE, TARGET) as any[];
    expect(rewritten[0].changes_added[0].raw).toEqual(filters(TARGET));
  });

  it('should collapse a value that became the target twice', () => {
    const rewritten = userMergeRewriteHistoryChanges([change('Report--objectAssignee', [{ raw: SOURCE }, { raw: TARGET }])], SOURCE, TARGET) as any[];
    expect(rewritten[0].changes_added).toEqual([{ raw: TARGET }]);
  });

  it('should keep the target entry of a label map naming both accounts', () => {
    const both = JSON.stringify({ [SOURCE]: 'source user', [TARGET]: 'target user' });
    const rewritten = userMergeRewriteHistoryChanges([change('Report--objectAssignee', [{ raw: OTHER, translated: both }])], SOURCE, TARGET) as any[];
    expect(JSON.parse(rewritten[0].changes_added[0].translated)).toEqual({ [TARGET]: 'target user' });
  });

  it('should not rewrite an id merely embedded in a longer string', () => {
    expect(userMergeRewriteHistoryChanges([change('Report--description', [{ raw: `see ${SOURCE}-archive for details` }])], SOURCE, TARGET)).toBeNull();
  });
});
