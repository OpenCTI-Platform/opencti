import { describe, expect, it } from 'vitest';
import { userMergeRewriteHistoryPayload } from '../../../../src/modules/userMerge/userMerge-historyPayloadHandler';

const SOURCE = '11111111-1111-4111-8111-111111111111';
const TARGET = '22222222-2222-4222-8222-222222222222';

describe('history context data payload rewriting', () => {
  it('should leave a record naming neither account untouched', () => {
    const record = { input: { user_id: 'someone-else' }, list_params: { orderBy: 'created_at' } };
    expect(userMergeRewriteHistoryPayload(record, SOURCE, TARGET)).toEqual({ rewritten: null, unparsable: false });
  });

  it('should rewrite the source inside a structured input payload', () => {
    const { rewritten, unparsable } = userMergeRewriteHistoryPayload({ input: { recipients: [SOURCE, 'other'] } }, SOURCE, TARGET);
    expect(rewritten?.input).toEqual({ recipients: [TARGET, 'other'] });
    expect(unparsable).toBe(false);
  });

  it('should rewrite the source inside the serialized filters and keep them serialized', () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: 'creator_id', values: [SOURCE] }], filterGroups: [] });
    const { rewritten } = userMergeRewriteHistoryPayload({ filters }, SOURCE, TARGET);
    expect(JSON.parse(rewritten?.filters as string).filters[0].values).toEqual([TARGET]);
  });

  it('should collapse a value that became the target twice', () => {
    const { rewritten } = userMergeRewriteHistoryPayload({ history_changes: { added: [SOURCE, TARGET] } }, SOURCE, TARGET);
    expect(rewritten?.history_changes).toEqual({ added: [TARGET] });
  });

  // Editing a filter field records the new filters serialized inside the mutation input.
  it('should rewrite the source inside a filter serialized in the input', () => {
    const filters = (user: string) => JSON.stringify({ mode: 'and', filters: [{ key: ['creator_id'], values: [user] }], filterGroups: [] });
    const { rewritten } = userMergeRewriteHistoryPayload({ input: [{ key: 'filters', value: [filters(SOURCE)] }] as never }, SOURCE, TARGET);
    expect(rewritten?.input).toEqual([{ key: 'filters', value: [filters(TARGET)] }]);
  });

  it('should not rewrite an id merely embedded in a longer string', () => {
    const record = { input: { note: `see ${SOURCE}-archive for details` } };
    expect(userMergeRewriteHistoryPayload(record, SOURCE, TARGET)).toEqual({ rewritten: null, unparsable: false });
  });

  // An unreadable payload is reported rather than rewritten: a string substitution cannot tell a
  // whole value from a substring, and this is an audit record.
  it('should report filters that name the source but do not parse, and rewrite nothing', () => {
    const record = { filters: `{"broken": [${SOURCE}` };
    expect(userMergeRewriteHistoryPayload(record, SOURCE, TARGET)).toEqual({ rewritten: null, unparsable: true });
  });

  // The unreadable filters must not take the rest of the record down with them: the input is still
  // rewritten, the filters are left as recorded, and the record is still reported.
  it('should keep rewriting the other fields of a record whose filters do not parse', () => {
    const filters = `{"broken": [${SOURCE}`;
    const record = { input: { objectAssignee: [SOURCE] }, list_params: { authorizedMembers: [SOURCE] }, filters };
    const { rewritten, unparsable } = userMergeRewriteHistoryPayload(record, SOURCE, TARGET);
    expect(rewritten?.input).toEqual({ objectAssignee: [TARGET] });
    expect(rewritten?.list_params).toEqual({ authorizedMembers: [TARGET] });
    expect(rewritten?.filters).toEqual(filters);
    expect(unparsable).toBe(true);
  });

  it('should report nothing when filters are unreadable but name another account', () => {
    expect(userMergeRewriteHistoryPayload({ filters: '{"broken": [' }, SOURCE, TARGET)).toEqual({ rewritten: null, unparsable: false });
  });

  // Readable, so not an unparsable payload: the id sits inside a value rather than as one, and an
  // audit record keeps what was typed.
  it('should not report filters that parse and only mention the id inside a value', () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: 'name', values: [`created by ${SOURCE}`] }], filterGroups: [] });
    expect(userMergeRewriteHistoryPayload({ filters }, SOURCE, TARGET)).toEqual({ rewritten: null, unparsable: false });
  });

  // The same remapper as the filter handler, so an id nested in serialized JSON inside the filters
  // is reached here too.
  it('should reach the source inside filters nested in serialized JSON', () => {
    const filters = JSON.stringify({ configuration: JSON.stringify({ values: [SOURCE] }) });
    const { rewritten } = userMergeRewriteHistoryPayload({ filters }, SOURCE, TARGET);
    expect(JSON.parse(JSON.parse(rewritten?.filters as string).configuration)).toEqual({ values: [TARGET] });
  });

  it('should rewrite several payload fields in the same record', () => {
    const { rewritten } = userMergeRewriteHistoryPayload(
      { input: { creator: SOURCE }, list_params: { authorizedMembers: [SOURCE] } },
      SOURCE,
      TARGET,
    );
    expect(rewritten?.input).toEqual({ creator: TARGET });
    expect(rewritten?.list_params).toEqual({ authorizedMembers: [TARGET] });
  });
});
