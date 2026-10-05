import type { PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../../relay/environment';

/**
 * useApiMutation forwards GraphQL payload errors to onCompleted: notify them and tell the caller
 * to stop, so a rejected mutation never closes a form or reports a success.
 */
export const notifyPayloadErrors = (errors: readonly PayloadError[] | null | undefined): boolean => {
  if (!errors || errors.length === 0) {
    return false;
  }
  MESSAGING$.notifyError(errors.map((error) => error.message).join(', '));
  return true;
};
