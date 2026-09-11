import { testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { userDelete, userEditField } from '../../../../src/domain/user';
import { USER_MERGED_INTO_FIELD } from '../../../../src/modules/userMerge/userMerge-types';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { isNotEmptyField } from '../../../../src/database/utils';
import type { BasicStoreEntity } from '../../../../src/types/store';

type MergeableUser = BasicStoreEntity & { [USER_MERGED_INTO_FIELD]?: string };

/**
 * Deletes a user a merge may have run on, the way an operator has to.
 *
 * `userDelete` refuses an account carrying the merge mark, because its cascades delete objects that
 * now belong to the target. Clearing the mark first is the documented way out, and these fixtures
 * are the only place that exercises it — a helper that bypassed the guard would leave the escape
 * hatch untested and let a future change close it without a single test noticing.
 *
 * Only the source of a merge carries the mark, so clearing it unconditionally would write on the
 * target for nothing. That write is not free: any update on a user re-aligns the individual joined
 * on its email, which on a re-pointed individual renames it and emits a stream event a test file
 * has no business emitting from its teardown.
 */
export const deleteMergeableUser = async (userId: string) => {
  const user = await storeLoadById<MergeableUser>(testContext, SYSTEM_USER, userId, ENTITY_TYPE_USER);
  if (isNotEmptyField(user?.[USER_MERGED_INTO_FIELD])) {
    await userEditField(testContext, SYSTEM_USER, userId, [{ key: USER_MERGED_INTO_FIELD, value: [null] }]);
  }
  await userDelete(testContext, SYSTEM_USER, userId);
};
