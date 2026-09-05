import { testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { userDelete, userEditField } from '../../../../src/domain/user';
import { USER_MERGED_INTO_FIELD } from '../../../../src/modules/userMerge/userMerge-types';

/**
 * Deletes a user a merge may have run on, the way an operator has to.
 *
 * `userDelete` refuses an account carrying the merge mark, because its cascades delete objects that
 * now belong to the target. Clearing the mark first is the documented way out, and these fixtures
 * are the only place that exercises it — a helper that bypassed the guard would leave the escape
 * hatch untested and let a future change close it without a single test noticing.
 */
export const deleteMergeableUser = async (userId: string) => {
  await userEditField(testContext, SYSTEM_USER, userId, [{ key: USER_MERGED_INTO_FIELD, value: [null] }]);
  await userDelete(testContext, SYSTEM_USER, userId);
};
