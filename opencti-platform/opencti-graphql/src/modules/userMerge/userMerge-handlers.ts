import { assertUserMergeHandlersAreValid, registerUserMergeHandler } from './userMerge-registry';
import { userMergePublicSharingHandler } from './userMerge-publicSharingHandler';
import { userMergeScalarHandler } from './userMerge-scalarHandler';

/**
 * Single registration point, and the only place the handler set is validated.
 *
 * Exported rather than run as a side effect of the import so that suites resetting the
 * registry can put it back in a known state. Validation runs last, on the complete set.
 */
export const registerUserMergeHandlers = (): void => {
  registerUserMergeHandler(userMergeScalarHandler);
  registerUserMergeHandler(userMergePublicSharingHandler);
  assertUserMergeHandlersAreValid();
};
