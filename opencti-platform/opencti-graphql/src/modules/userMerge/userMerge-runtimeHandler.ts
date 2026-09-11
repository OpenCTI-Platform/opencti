import { BUS_TOPICS } from '../../config/conf';
import { updateAttribute } from '../../database/middleware';
import { delUserContext, fetchUserContextIds, notify, redisDelForgotPassword, redisGetForgotPasswordOtpPointer } from '../../database/redis';
import { delTokensUsage, getTokensUsage } from '../../database/redis/token_usage';
import { findUserSessions, killUserSessions } from '../../database/session';
import { UPDATE_OPERATION_REMOVE } from '../../database/utils';
import type { EditOperation } from '../../generated/graphql';
import { closeUserStreamConnections, userStreamConnections } from '../../graphql/sseMiddleware';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, type UserMergePlannedChange } from './userMerge-handler';

export const USER_MERGE_RUNTIME_HANDLER = 'source-runtime-invalidation';

const FIELD_API_TOKENS = 'api_tokens';

interface RuntimeContext {
  context: AuthContext;
  sourceUser: AuthUser;
}

/**
 * One means of access the source keeps, with the way to observe it and the way to close it.
 *
 * Declared as data rather than as a sequence of calls so that the register row, what the report
 * shows and what `apply` destroys cannot drift apart: a row added here is counted and invalidated
 * by construction.
 */
interface RuntimeInvalidation {
  registerRow: string;
  /** Rows destroyed by the very same call, reported with the same count. */
  alsoCovers?: string[];
  entityType: string;
  detail: string;
  /** Pure read, run in both passes. */
  count: (runtime: RuntimeContext) => Promise<number>;
  invalidate: (runtime: RuntimeContext) => Promise<number>;
}

const INVALIDATIONS: RuntimeInvalidation[] = [
  {
    // Before the revocation, deliberately. The usage keys never expire and are only nameable from
    // the token ids, so a run that failed after the revocation could no longer find them.
    registerRow: 'api-token.usage-key',
    entityType: ENTITY_TYPE_USER,
    detail: 'token usage keys dropped',
    count: async ({ sourceUser }) => {
      // A key only exists once the token has been used, so the token count would overstate it —
      // and this row is reported as exact.
      const tokenIds = (sourceUser.api_tokens ?? []).map((token) => token.id);
      return Object.keys(await getTokensUsage(tokenIds)).length;
    },
    invalidate: async ({ sourceUser }) => {
      const tokenIds = (sourceUser.api_tokens ?? []).map((token) => token.id);
      return tokenIds.length > 0 ? delTokensUsage(tokenIds) : 0;
    },
  },
  {
    registerRow: 'user.api-tokens',
    entityType: ENTITY_TYPE_USER,
    detail: 'API tokens revoked',
    count: async ({ sourceUser }) => (sourceUser.api_tokens ?? []).length,
    invalidate: async ({ context, sourceUser }) => {
      const tokens = sourceUser.api_tokens ?? [];
      if (tokens.length === 0) {
        return 0;
      }
      // One operation carrying every token, not one per token: `updateAttribute` rebuilds each
      // input from the same initial user, so several removals on one attribute overwrite each
      // other and the last one wins — leaving a usable token on the account.
      const update = { key: FIELD_API_TOKENS, value: tokens, operation: UPDATE_OPERATION_REMOVE as EditOperation };
      const { element } = await updateAttribute(context, SYSTEM_USER, sourceUser.id, ENTITY_TYPE_USER, [update]);
      // `updateAttribute` writes the entity but publishes nothing, and the user cache is what the
      // API resolves a token against: without this the revoked tokens keep authenticating until
      // the cache happens to be rebuilt. The regular revocation path notifies for the same reason.
      await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, SYSTEM_USER);
      return tokens.length;
    },
  },
  {
    registerRow: 'session.key',
    // `killSession` deletes the session key and its entry in the `platform_sessions` sorted set in
    // the same operation, so the index row cannot be closed separately from the key it points to.
    alsoCovers: ['session.platform-sessions'],
    entityType: ENTITY_TYPE_USER,
    detail: 'sessions destroyed',
    count: async ({ sourceUser }) => (await findUserSessions(sourceUser.id)).length,
    invalidate: async ({ sourceUser }) => (await killUserSessions(sourceUser.id)).length,
  },
  {
    registerRow: 'edit-context.keys',
    entityType: ENTITY_TYPE_USER,
    detail: 'edit context locks released',
    count: async ({ sourceUser }) => (await fetchUserContextIds(sourceUser.id)).length,
    invalidate: async ({ sourceUser }) => (await delUserContext(sourceUser)).length,
  },
  {
    registerRow: 'password-reset.keys',
    entityType: ENTITY_TYPE_USER,
    detail: 'pending password reset dropped',
    count: async ({ sourceUser }) => {
      const { id } = await redisGetForgotPasswordOtpPointer(sourceUser.user_email);
      return id ? 1 : 0;
    },
    invalidate: async ({ sourceUser }) => {
      const { id } = await redisGetForgotPasswordOtpPointer(sourceUser.user_email);
      if (!id) {
        return 0;
      }
      await redisDelForgotPassword(id, sourceUser.user_email);
      return 1;
    },
  },
  {
    registerRow: 'client-connection.auth-context',
    entityType: ENTITY_TYPE_USER,
    detail: 'live stream connections closed on this node',
    count: async ({ sourceUser }) => userStreamConnections(sourceUser.id).length,
    invalidate: async ({ sourceUser }) => closeUserStreamConnections(sourceUser.id),
  },
];

/**
 * Rows this handler answers for by establishing that nothing has to be done, and why.
 *
 * They are claimed rather than left uncovered on purpose: an uncovered row reads as an oversight,
 * and the next person would have to redo the analysis to find out it was a decision.
 */
const ACKNOWLEDGED_ROWS: Array<{ registerRow: string; entityType: string; detail: string }> = [
  {
    registerRow: 'user.password',
    entityType: ENTITY_TYPE_USER,
    detail: 'kept: the account is disabled and its tokens revoked, so the password opens nothing',
  },
  {
    registerRow: 'user.otp',
    entityType: ENTITY_TYPE_USER,
    detail: 'kept: a second factor guards an authentication the account can no longer pass',
  },
  {
    registerRow: 'user.administration-fields',
    entityType: ENTITY_TYPE_USER,
    detail: 'kept on the source: a merge does not transfer them, and they grant nothing once disabled',
  },
  {
    registerRow: 'auth-user.cache-entries',
    entityType: ENTITY_TYPE_USER,
    detail: 'invalidated by the platform: the token revocation notifies the user cache',
  },
  {
    registerRow: 'sso.session-and-refresh-token',
    entityType: ENTITY_TYPE_USER,
    detail: 'not actionable: the session and refresh token live at the identity provider',
  },
];

/**
 * Closes every means of access the source keeps once the merge is applied.
 *
 * Runs last, deliberately. The source deactivation runs first and already blocks authentication —
 * every entry point resolves through `validateUser`, which refuses any account status other than
 * active — so this is not what stops the merged-away account from logging in. What it does is turn
 * a reversible block into a definitive one: re-activating the account would otherwise re-arm every
 * API token it still holds, which is precisely what the feature asks not to happen.
 *
 * Both passes read the pre-merge state: the engine computes and verifies every handler before any
 * of them writes, so the counts reported here are the ones the operator reviewed. Sessions are
 * where that matters — the deactivation kills them once the write phase starts, so `apply` usually
 * finds none left. Killing them again is what makes the guarantee this handler carries independent
 * of a side effect in `userEditField`.
 *
 * Redis keys are not declared in `reads`/`writes`: those express field paths, used for the
 * read/write disjointness check between handlers, and no other handler reads them.
 */
export const userMergeRuntimeHandler: UserMergeHandler = {
  identifier: USER_MERGE_RUNTIME_HANDLER,
  covers: [
    ...INVALIDATIONS.flatMap((invalidation) => [invalidation.registerRow, ...(invalidation.alsoCovers ?? [])]),
    ...ACKNOWLEDGED_ROWS.map((row) => row.registerRow),
  ],
  reads: [`${ENTITY_TYPE_USER}.${FIELD_API_TOKENS}`],
  writes: [`${ENTITY_TYPE_USER}.${FIELD_API_TOKENS}`],
  compute: async ({ context, sourceUser }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const runtime: RuntimeContext = { context, sourceUser };
    const changes: UserMergePlannedChange[] = [];
    for (let i = 0; i < INVALIDATIONS.length; i += 1) {
      const invalidation = INVALIDATIONS[i];
      const count = await invalidation.count(runtime);
      changes.push({
        register_row_id: invalidation.registerRow,
        entity_type: invalidation.entityType,
        count,
        exact: true,
        detail: invalidation.detail,
      });
      (invalidation.alsoCovers ?? []).forEach((registerRow) => {
        changes.push({ register_row_id: registerRow, entity_type: invalidation.entityType, count, exact: true, detail: invalidation.detail });
      });
    }
    ACKNOWLEDGED_ROWS.forEach((row) => {
      changes.push({ register_row_id: row.registerRow, entity_type: row.entityType, count: 0, exact: true, detail: row.detail });
    });
    return { handler: USER_MERGE_RUNTIME_HANDLER, changes, alerts: [] };
  },
  /**
   * Every invalidation is attempted, whatever the plan announced.
   *
   * The other handlers skip the rows they planned at zero, because re-running their bulk update
   * would be a write for nothing. Here the plan is a photograph of a moment before the merge
   * started writing, and the point of the pass is that nothing is left open when it ends — a
   * session opened between the two would be exactly what has to be closed.
   */
  apply: async ({ context, sourceUser }: UserMergeHandlerContext): Promise<number> => {
    const runtime: RuntimeContext = { context, sourceUser };
    let invalidated = 0;
    for (let i = 0; i < INVALIDATIONS.length; i += 1) {
      invalidated += await INVALIDATIONS[i].invalidate(runtime);
    }
    return invalidated;
  },
};
