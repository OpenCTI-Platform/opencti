import { ACCOUNT_STATUS_EXPIRED } from '../../config/conf';
import { storeLoadById } from '../../database/middleware-loader';
import { userEditField } from '../../domain/user';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, USER_MERGE_SOURCE_DISABLE_HANDLER } from './userMerge-handler';
import { USER_MERGED_INTO_FIELD } from './userMerge-types';

const ACCOUNT_STATUS_FIELD = 'account_status';
const SOURCE_DISABLE_ROW = 'user.account-status';
const DISABLED = 'source account disabled, its sessions killed, merge target recorded on it';

interface SourceAccountState {
  account_status?: string;
  merged_into?: string;
}

/**
 * Read from the store rather than from `handlerContext.sourceUser`.
 *
 * The context holds a cache snapshot resolved once before both passes. A re-run — the recovery
 * path of a partial merge — would recompute from a cache that may not have been invalidated yet
 * and disable an already disabled account, writing a second audit event for nothing.
 */
const readSourceAccountState = async (context: AuthContext, sourceId: string): Promise<SourceAccountState> => {
  const source = await storeLoadById<BasicStoreCommon & SourceAccountState>(context, SYSTEM_USER, sourceId, ENTITY_TYPE_USER);
  return { account_status: source?.account_status, merged_into: source?.merged_into };
};

/**
 * Disables the source account, before any other handler runs.
 *
 * Ordering is deliberate: from the moment the merge starts writing, the source must no longer be
 * able to authenticate and produce the very references the following handlers are moving. The
 * engine computes every handler before any of them writes, so this only ever runs once the whole
 * dry pass succeeded — a failed computation does not leave a disabled account behind.
 *
 * `Expired` and not `Locked`: `Locked` exists as a constant but is absent from the default status
 * table, so writing it would put the account in a state the platform does not offer.
 *
 * Only `account_status` is written from the register row, although the row also names
 * `account_lock_after_date`. The platform itself leaves that date untouched when a status moves to
 * `Expired` — the reset is conditioned on a status other than `Expired`. The merge reproduces an
 * administrator disabling an account, it does not extend it.
 *
 * `merged_into` is written alongside it, and it is not part of the row: the row asks for the source
 * to be closed, this field asks for it to be recognisable afterwards. `userDelete` reads it and
 * refuses, because the ordinary deletion path runs four cascades that select by a reference to this
 * account — after a merge those objects belong to the target, so a reference the merge missed makes
 * a cascade delete one of them rather than skip it. The field is deliberately left editable: a
 * source that can never be deleted again would be a worse outcome than one deleted deliberately.
 */
export const userMergeSourceDisableHandler: UserMergeHandler = {
  identifier: USER_MERGE_SOURCE_DISABLE_HANDLER,
  covers: [SOURCE_DISABLE_ROW],
  reads: [`${ENTITY_TYPE_USER}.${ACCOUNT_STATUS_FIELD}`, `${ENTITY_TYPE_USER}.${USER_MERGED_INTO_FIELD}`],
  writes: [`${ENTITY_TYPE_USER}.${ACCOUNT_STATUS_FIELD}`, `${ENTITY_TYPE_USER}.${USER_MERGED_INTO_FIELD}`],
  compute: async ({ context, sourceId, targetId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const state = await readSourceAccountState(context, sourceId);
    // Both conditions, not just the status: an account an administrator had already expired before
    // the merge would otherwise never get the mark, and the ordinary deletion path would stay open
    // on exactly the account the merge just emptied.
    const done = state.account_status === ACCOUNT_STATUS_EXPIRED && state.merged_into === targetId;
    const count = done ? 0 : 1;
    return {
      handler: USER_MERGE_SOURCE_DISABLE_HANDLER,
      // Emitted even at zero, so the report names the account state it observed rather than
      // staying silent on the one operation the operator most needs to see before validating.
      changes: [{ register_row_id: SOURCE_DISABLE_ROW, entity_type: ENTITY_TYPE_USER, count, exact: true, detail: DISABLED }],
      alerts: [],
    };
  },
  /**
   * Written through the domain layer: `userEditField` kills the source sessions as a side effect
   * of the status change, which a raw index write would not do.
   */
  apply: async ({ context, sourceId, targetId }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = plan.changes.some((change) => change.register_row_id === SOURCE_DISABLE_ROW && change.count > 0);
    if (!planned) {
      return 0;
    }
    await userEditField(context, SYSTEM_USER, sourceId, [
      { key: ACCOUNT_STATUS_FIELD, value: [ACCOUNT_STATUS_EXPIRED] },
      { key: USER_MERGED_INTO_FIELD, value: [targetId] },
    ]);
    return 1;
  },
};
