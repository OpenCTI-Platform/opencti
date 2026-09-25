import { assertUserMergeHandlersAreValid, registerUserMergeHandler } from './userMerge-registry';
import { userMergeHistoryHandler } from './userMerge-historyHandler';
import { userMergeIndividualHandler } from './userMerge-individualHandler';
import { userMergeOperationalRelationsHandler } from './userMerge-operationalRelationsHandler';
import { userMergePublicSharingHandler } from './userMerge-publicSharingHandler';
import { userMergeRightsHandler } from './userMerge-rightsHandler';
import { userMergeRuntimeHandler } from './userMerge-runtimeHandler';
import { userMergeScalarHandler } from './userMerge-scalarHandler';
import { userMergeSourceDisableHandler } from './userMerge-sourceDisableHandler';

/**
 * Single registration point, and the only place the handler set is validated.
 *
 * Exported rather than run as a side effect of the import so that suites resetting the
 * registry can put it back in a known state. Validation runs last, on the complete set.
 */
export const registerUserMergeHandlers = (): void => {
  // Registration order is execution order. The source is disabled first, so that it cannot
  // authenticate and create new references while the following handlers move the existing ones.
  registerUserMergeHandler(userMergeSourceDisableHandler);
  registerUserMergeHandler(userMergeScalarHandler);
  registerUserMergeHandler(userMergeHistoryHandler);
  registerUserMergeHandler(userMergePublicSharingHandler);
  registerUserMergeHandler(userMergeRightsHandler);
  registerUserMergeHandler(userMergeOperationalRelationsHandler);
  registerUserMergeHandler(userMergeIndividualHandler);
  // Last: the source keeps its live accesses for the whole merge, so that a handler failing
  // halfway leaves an account an administrator can still inspect rather than one already stripped.
  registerUserMergeHandler(userMergeRuntimeHandler);
  assertUserMergeHandlersAreValid();
};
