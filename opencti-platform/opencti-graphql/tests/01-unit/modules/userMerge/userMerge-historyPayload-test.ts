import { describe, expect, it } from 'vitest';
import { userMergeRewriteHistoryPayload } from '../../../../src/modules/userMerge/userMerge-historyPayloadHandler';

const SOURCE = '11111111-1111-4111-8111-111111111111';
const TARGET = '22222222-2222-4222-8222-222222222222';

describe('history context data payload rewriting', () => {
  it('should leave a record naming neither account untouched', () => {
    const record = { input: { user_id: 'someone-else' }, list_params: { orderBy: 'created_at' } };
    expect(userMergeRewriteHistoryPayload(record, SOURCE, TARGET)).toBeNull();
  });

  it('should rewrite the source inside a structured input payload', () => {
    const rewritten = userMergeRewriteHistoryPayload({ input: { recipients: [SOURCE, 'other'] } }, SOURCE, TARGET);
    expect(rewritten?.input).toEqual({ recipients: [TARGET, 'other'] });
  });

  it('should rewrite the source inside the serialized filters and keep them serialized', () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: 'creator_id', values: [SOURCE] }], filterGroups: [] });
    const rewritten = userMergeRewriteHistoryPayload({ filters }, SOURCE, TARGET);
    expect(JSON.parse(rewritten?.filters as string).filters[0].values).toEqual([TARGET]);
  });

  it('should collapse a value that became the target twice', () => {
    const rewritten = userMergeRewriteHistoryPayload({ history_changes: { added: [SOURCE, TARGET] } }, SOURCE, TARGET);
    expect(rewritten?.history_changes).toEqual({ added: [TARGET] });
  });

  it('should not rewrite an id merely embedded in a longer string', () => {
    const record = { input: { note: `see ${SOURCE}-archive for details` } };
    expect(userMergeRewriteHistoryPayload(record, SOURCE, TARGET)).toBeNull();
  });

  // An unreadable payload is reported rather than rewritten: a string substitution cannot tell a
  // whole value from a substring, and this is an audit record.
  it('should refuse to rewrite filters that do not parse', () => {
    expect(userMergeRewriteHistoryPayload({ filters: `{"broken": [${SOURCE}` }, SOURCE, TARGET)).toBeNull();
  });

  it('should report nothing when filters are unreadable but name another account', () => {
    expect(userMergeRewriteHistoryPayload({ filters: '{"broken": [' }, SOURCE, TARGET)).toBeNull();
  });

  it('should rewrite several payload fields in the same record', () => {
    const rewritten = userMergeRewriteHistoryPayload(
      { input: { creator: SOURCE }, list_params: { authorizedMembers: [SOURCE] } },
      SOURCE,
      TARGET,
    );
    expect(rewritten?.input).toEqual({ creator: TARGET });
    expect(rewritten?.list_params).toEqual({ authorizedMembers: [TARGET] });
  });
});
