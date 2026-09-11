import { assertUserMergeHandlersAreValid } from './userMerge-registry';

/**
 * Single registration point, and the only place the handler set is validated.
 *
 * Exported rather than run as a side effect of the import so that suites resetting the
 * registry can put it back in a known state. Handlers are added here as the chunks land;
 * validation runs last, on the complete set.
 */
export const registerUserMergeHandlers = (): void => {
  assertUserMergeHandlersAreValid();
};
