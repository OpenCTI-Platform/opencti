import type { PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../relay/environment';

/**
 * useApiMutation hands GraphQL payload errors to onCompleted, not to onError: they are notified here and the caller
 * skips its success path when this returns true.
 */
export const notifyPayloadErrors = (errors: readonly PayloadError[] | null | undefined): boolean => {
  if (!errors || errors.length === 0) {
    return false;
  }
  errors.forEach((error) => MESSAGING$.notifyError(error.message));
  return true;
};
