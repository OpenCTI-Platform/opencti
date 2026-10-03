import { UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { UserMergeHandler } from './userMerge-handler';
import { USER_MERGE_SOURCE_DISABLE_HANDLER } from './userMerge-handler';
import { findRegisterRow } from './userMerge-register';

const HANDLERS: UserMergeHandler[] = [];

/**
 * Identity fields a merge never writes, on either account.
 *
 * The merge moves owned objects, it does not reconcile identities: the target keeps its own
 * profile whatever the source carries. Only one handler comes close to writing these — the
 * one closing the source account, exempted below — so this guards against a future one rather
 * than fixing a present bug.
 *
 * Both accounts are protected, not just the target: nothing in the feature asks to rewrite the
 * source's identity either, and a rule stated on one side only would need the handler to
 * declare which account it writes to, which `writes` does not express.
 *
 * When the target is SSO-provisioned the platform already refuses the write and re-patches the
 * fields from the IdP at every login. This covers the case where both accounts are local, where
 * nothing stops it.
 *
 * `password_valid_until` and `account_lock_after_date` are here for what they do, not because the
 * register groups them with `password` and `account_status`: a date in the past forces a password
 * reset on the target, and a lock date locks it out. Guarding the status without them would leave
 * a handler able to reach the same authentication state by another field.
 */
const PROTECTED_USER_FIELDS = [
  'name', 'user_email', 'firstname', 'lastname', 'external',
  'password', 'password_valid_until',
  'account_status', 'account_lock_after_date',
];

/**
 * The one exemption, named rather than inferred.
 *
 * `account_status` belongs to the retained identity row, and the merge still writes it: closing
 * the source is an invalidate row of its own (`user.account-status`). Since `writes` carries no
 * source/target axis, naming the single handler allowed to touch it is the only way to state
 * "on the source, by this handler alone". Any other handler asking for the field is refused,
 * which is what stops a future one from overwriting the target's status.
 */
const SOURCE_STATUS_FIELD = `${ENTITY_TYPE_USER}.account_status`;

const assertNoProfileWrite = (handler: UserMergeHandler): void => {
  const protectedPaths = PROTECTED_USER_FIELDS.map((field) => `${ENTITY_TYPE_USER}.${field}`);
  const exempted = (field: string) => field === SOURCE_STATUS_FIELD && handler.identifier === USER_MERGE_SOURCE_DISABLE_HANDLER;
  const violations = handler.writes.filter((field) => protectedPaths.includes(field) && !exempted(field));
  if (violations.length > 0) {
    throw UnsupportedError('Merge handler writes user identity fields, which a merge never rewrites', {
      handler: handler.identifier,
      fields: violations,
    });
  }
};

const assertCoverageIsValid = (handler: UserMergeHandler): void => {
  const unknownRows = handler.covers.filter((rowId) => !findRegisterRow(rowId));
  if (unknownRows.length > 0) {
    throw UnsupportedError('Merge handler declares coverage on register rows that do not exist', {
      handler: handler.identifier,
      unknown_rows: unknownRows,
    });
  }
};

/**
 * Read/write disjointness — the clause the whole model rests on.
 *
 * In the dry pass nothing is written, so a handler running late sees the pre-merge state; in
 * the real pass it would see what earlier handlers already wrote. Disjointness is what
 * guarantees both situations produce the same result. Without it, dry-run and run diverge
 * silently — hence a startup error rather than a silent corruption.
 */
export const assertHandlersAreDisjoint = (handlers: UserMergeHandler[]): void => {
  handlers.forEach((reader) => {
    handlers.forEach((writer) => {
      if (reader.identifier === writer.identifier) {
        return; // a handler reading what it writes is inherent, not a conflict
      }
      const intersection = reader.reads.filter((field) => writer.writes.includes(field));
      if (intersection.length > 0) {
        throw UnsupportedError('Merge handlers are not read/write disjoint', {
          reader: reader.identifier,
          writer: writer.identifier,
          fields: intersection,
        });
      }
    });
  });
};

const assertNoDuplicateClaim = (handlers: UserMergeHandler[]): void => {
  const claimedBy = new Map<string, string>();
  handlers.forEach((handler) => {
    handler.covers.forEach((rowId) => {
      const existing = claimedBy.get(rowId);
      if (existing) {
        throw UnsupportedError('Two merge handlers claim the same register row', {
          row_id: rowId,
          handlers: [existing, handler.identifier],
        });
      }
      claimedBy.set(rowId, handler.identifier);
    });
  });
};

/**
 * Registers a handler. Only what concerns the handler alone is checked here; what concerns
 * the set is checked once the set is complete, by assertUserMergeHandlersAreValid.
 */
export const registerUserMergeHandler = (handler: UserMergeHandler): void => {
  if (HANDLERS.some((existing) => existing.identifier === handler.identifier)) {
    throw UnsupportedError('A merge handler with this identifier is already registered', { handler: handler.identifier });
  }
  assertNoProfileWrite(handler);
  HANDLERS.push(handler);
};

/**
 * Validates the registered set, once it is complete.
 *
 * Disjointness and single-claim are properties of the set, not of a handler: checking them on
 * every insertion re-derives the same answer N times and answers about a set that is not yet
 * the one the engine will run. Called from the registration function so that a mistake still
 * surfaces when the platform boots rather than when a merge is launched.
 */
export const assertUserMergeHandlersAreValid = (handlers: UserMergeHandler[] = HANDLERS): void => {
  handlers.forEach(assertCoverageIsValid);
  assertNoDuplicateClaim(handlers);
  assertHandlersAreDisjoint(handlers);
};

export const userMergeHandlers = (): UserMergeHandler[] => [...HANDLERS];

/** Test seam: the registry is module-level state, and suites need a clean slate. */
export const resetUserMergeHandlers = (): void => {
  HANDLERS.length = 0;
};
