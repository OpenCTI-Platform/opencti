import { registerUserMergeHandler } from './userMerge-registry';
import { userMergePublicSharingHandler } from './userMerge-publicSharingHandler';
import { userMergeScalarHandler } from './userMerge-scalarHandler';

/**
 * Single registration point. Exported rather than run as a side effect of the import so that
 * suites resetting the registry can put it back in a known state.
 */
export const registerUserMergeHandlers = (): void => {
  registerUserMergeHandler(userMergeScalarHandler);
  registerUserMergeHandler(userMergePublicSharingHandler);
};
