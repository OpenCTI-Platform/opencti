import { ACCOUNT_STATUS_EXPIRED } from '../../config/conf';
import { storeLoadById } from '../../database/middleware-loader';
import { userEditField } from '../../domain/user';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type UserMergeHandler, type UserMergeHandlerContext, type UserMergeHandlerPlan, USER_MERGE_SOURCE_DISABLE_HANDLER } from './userMerge-handler';

const ACCOUNT_STATUS_FIELD = 'account_status';
const SOURCE_DISABLE_ROW = 'user.account-status';
const DISABLED = 'source account disabled, its sessions killed';

/**
 * Read from the store rather than from `handlerContext.sourceUser`.
 *
 * The context holds a cache snapshot resolved once before both passes. A re-run — the recovery
 * path of a partial merge — would recompute from a cache that may not have been invalidated yet
 * and disable an already disabled account, writing a second audit event for nothing.
 */
const readAccountStatus = async (context: AuthContext, sourceId: string): Promise<string | undefined> => {
  const source = await storeLoadById<BasicStoreCommon & { account_status?: string }>(context, SYSTEM_USER, sourceId, ENTITY_TYPE_USER);
  return source?.account_status;
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
 * Only `account_status` is written, although the register row also names `account_lock_after_date`.
 * The platform itself leaves that date untouched when a status moves to `Expired` — the reset is
 * conditioned on a status other than `Expired`. The merge reproduces an administrator disabling an
 * account, it does not extend it.
 */
export const userMergeSourceDisableHandler: UserMergeHandler = {
  identifier: USER_MERGE_SOURCE_DISABLE_HANDLER,
  covers: [SOURCE_DISABLE_ROW],
  reads: [`${ENTITY_TYPE_USER}.${ACCOUNT_STATUS_FIELD}`],
  writes: [`${ENTITY_TYPE_USER}.${ACCOUNT_STATUS_FIELD}`],
  compute: async ({ context, sourceId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const accountStatus = await readAccountStatus(context, sourceId);
    const count = accountStatus === ACCOUNT_STATUS_EXPIRED ? 0 : 1;
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
  apply: async ({ context, sourceId }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = plan.changes.some((change) => change.register_row_id === SOURCE_DISABLE_ROW && change.count > 0);
    if (!planned) {
      return 0;
    }
    await userEditField(context, SYSTEM_USER, sourceId, [{ key: ACCOUNT_STATUS_FIELD, value: [ACCOUNT_STATUS_EXPIRED] }]);
    return 1;
  },
};
