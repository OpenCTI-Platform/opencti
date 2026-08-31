import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  handlerDryRun,
  planDivergence,
  planFingerprint,
  type UserMergeHandler,
  type UserMergeHandlerContext,
  USER_MERGE_SOURCE_DISABLE_HANDLER,
  USER_MERGE_TARGET_INDICES,
} from '../../../../src/modules/userMerge/userMerge-handler';
import {
  assertHandlersAreDisjoint,
  assertUserMergeHandlersAreValid,
  registerUserMergeHandler,
  resetUserMergeHandlers,
  userMergeHandlers,
} from '../../../../src/modules/userMerge/userMerge-registry';
import { UserMergeRightsStrategy } from '../../../../src/modules/userMerge/userMerge-types';
import { INDEX_DELETED_OBJECTS, READ_INDEX_DRAFT_OBJECTS } from '../../../../src/database/utils';

const EMPTY_RIGHTS = { markings: [], organizations: [], capabilities: [], groups: [] };

const handlerContext = {
  context: {} as never,
  sourceId: 'source',
  targetId: 'target',
  mergeStartedAt: new Date(),
  sourceUser: { internal_id: 'source' } as never,
  targetUser: { internal_id: 'target' } as never,
  rights: { source: EMPTY_RIGHTS, target: EMPTY_RIGHTS, projected: EMPTY_RIGHTS, labels: {} },
  options: { dryRun: true, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
} as UserMergeHandlerContext;

const mockHandler = (overrides: Partial<UserMergeHandler> = {}): UserMergeHandler => ({
  identifier: 'mock',
  covers: ['activity.user-id'],
  reads: ['activity.user_id'],
  writes: ['activity.user_id'],
  compute: async () => ({ handler: 'mock', changes: [], alerts: [] }),
  apply: async () => 0,
  ...overrides,
});

describe('Handler index scope', () => {
  it('should include the trash, which is restorable', () => {
    expect(USER_MERGE_TARGET_INDICES).toContain(INDEX_DELETED_OBJECTS);
  });
  it('should include the drafts, which survive the workers being stopped', () => {
    expect(USER_MERGE_TARGET_INDICES).toContain(READ_INDEX_DRAFT_OBJECTS);
  });
});

describe('Handler execution modes', () => {
  it('should never write in dry mode', async () => {
    const apply = vi.fn(async () => 42);
    const handler = mockHandler({ apply });
    const outcome = await handlerDryRun(handler, handlerContext);
    expect(apply).not.toHaveBeenCalled();
    expect(outcome.updated).toBe(0);
  });

  it('should give the same fingerprint whatever the order of the plan entries', async () => {
    const first = {
      handler: 'mock',
      changes: [
        { register_row_id: 'activity.user-id', entity_type: 'Activity', count: 3, exact: true },
        { register_row_id: 'user.password', entity_type: 'User', count: 1, exact: true },
      ],
      alerts: [],
    };
    const second = { ...first, changes: [...first.changes].reverse() };
    expect(planFingerprint(first)).toEqual(planFingerprint(second));
  });

  it('should give a different fingerprint when a count moves', async () => {
    const base = { handler: 'mock', changes: [{ register_row_id: 'user.password', entity_type: 'User', count: 1, exact: true }], alerts: [] };
    const moved = { ...base, changes: [{ ...base.changes[0], count: 2 }] };
    expect(planFingerprint(base)).not.toEqual(planFingerprint(moved));
  });

  it('should name the entries that moved between the two passes', async () => {
    const dry = {
      handler: 'mock',
      changes: [
        { register_row_id: 'user.password', entity_type: 'User', count: 1, exact: true },
        { register_row_id: 'activity.user-id', entity_type: 'Activity', count: 3, exact: true },
      ],
      alerts: [],
    };
    const real = { ...dry, changes: [dry.changes[0], { ...dry.changes[1], count: 4 }] };
    const divergence = planDivergence(dry, real);
    expect(divergence.dry_only).toEqual(['activity.user-id|Activity|3|true']);
    expect(divergence.real_only).toEqual(['activity.user-id|Activity|4|true']);
  });

  it('should report nothing when the two passes agree', async () => {
    const plan = { handler: 'mock', changes: [{ register_row_id: 'user.password', entity_type: 'User', count: 1, exact: true }], alerts: [] };
    expect(planDivergence(plan, { ...plan, changes: [...plan.changes] })).toEqual({ dry_only: [], real_only: [] });
  });
});

describe('Handler registry', () => {
  beforeEach(() => {
    resetUserMergeHandlers();
  });

  it('should register a valid handler', () => {
    registerUserMergeHandler(mockHandler());
    expect(userMergeHandlers().map((handler) => handler.identifier)).toEqual(['mock']);
  });

  it('should reject a duplicate identifier', () => {
    registerUserMergeHandler(mockHandler());
    expect(() => registerUserMergeHandler(mockHandler())).toThrow('already registered');
  });

  it('should reject coverage on a register row that does not exist', () => {
    registerUserMergeHandler(mockHandler({ covers: ['no-such-row'] }));
    expect(() => assertUserMergeHandlersAreValid(userMergeHandlers())).toThrow('register rows that do not exist');
  });

  it('should reject two handlers claiming the same register row', () => {
    registerUserMergeHandler(mockHandler());
    registerUserMergeHandler(mockHandler({ identifier: 'other', reads: ['other.field'], writes: ['other.field'] }));
    expect(() => assertUserMergeHandlersAreValid(userMergeHandlers())).toThrow('claim the same register row');
  });

  it('should reject a handler reading a field another handler writes', () => {
    registerUserMergeHandler(mockHandler({ identifier: 'writer', writes: ['shared.field'], reads: [] }));
    registerUserMergeHandler(mockHandler({ identifier: 'reader', covers: ['history.user-id'], reads: ['shared.field'], writes: [] }));
    expect(() => assertUserMergeHandlersAreValid(userMergeHandlers())).toThrow('not read/write disjoint');
  });

  it('should accept a well formed set', () => {
    registerUserMergeHandler(mockHandler());
    registerUserMergeHandler(mockHandler({ identifier: 'other', covers: ['history.user-id'], reads: ['other.field'], writes: ['other.field'] }));
    expect(() => assertUserMergeHandlersAreValid(userMergeHandlers())).not.toThrow();
  });

  it('should not treat a handler reading what it writes as a conflict', () => {
    expect(() => assertHandlersAreDisjoint([mockHandler({ reads: ['same.field'], writes: ['same.field'] })])).not.toThrow();
  });

  it('should reject a handler writing a user identity field', () => {
    expect(() => registerUserMergeHandler(mockHandler({ writes: ['User.user_email'] }))).toThrow('user identity fields');
  });

  it('should reject a handler other than the deactivation one writing the account status', () => {
    expect(() => registerUserMergeHandler(mockHandler({ writes: ['User.account_status'] }))).toThrow('user identity fields');
  });

  it('should accept the deactivation handler writing the account status', () => {
    // Named exemption rather than an unprotected field: closing the source is a write on the
    // source, and `writes` cannot say on which account, so the identifier is what scopes it.
    const disable = mockHandler({ identifier: USER_MERGE_SOURCE_DISABLE_HANDLER, writes: ['User.account_status'] });
    expect(() => registerUserMergeHandler(disable)).not.toThrow();
  });

  // The two fields that reach the same authentication state as the ones above by another path:
  // a validity date in the past forces a password reset on the target, a lock date locks it out.
  it('should reject a handler writing the password validity date', () => {
    expect(() => registerUserMergeHandler(mockHandler({ writes: ['User.password_valid_until'] }))).toThrow('user identity fields');
  });

  it('should reject a handler writing the account lock date', () => {
    expect(() => registerUserMergeHandler(mockHandler({ writes: ['User.account_lock_after_date'] }))).toThrow('user identity fields');
  });

  // The exemption is on the status alone. The deactivation handler leaves the lock date to the
  // platform, so extending its exemption to the whole row would grant more than it asks for.
  it('should reject the deactivation handler writing the account lock date', () => {
    const disable = mockHandler({ identifier: USER_MERGE_SOURCE_DISABLE_HANDLER, writes: ['User.account_lock_after_date'] });
    expect(() => registerUserMergeHandler(disable)).toThrow('user identity fields');
  });

  it('should accept a handler writing a user field that carries no identity', () => {
    expect(() => registerUserMergeHandler(mockHandler({ writes: ['User.personal_notifiers'] }))).not.toThrow();
  });

  it('should leave the registry untouched when a registration is refused', () => {
    registerUserMergeHandler(mockHandler());
    expect(() => registerUserMergeHandler(mockHandler())).toThrow();
    expect(userMergeHandlers()).toHaveLength(1);
  });
});
