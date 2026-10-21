import type { PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../../relay/environment';

/**
 * Relay completes a mutation that returned payload errors instead of failing it:
 * report the errors and tell the caller not to treat the mutation as successful.
 */
export const hasPayloadErrors = (errors: ReadonlyArray<PayloadError> | null | undefined): boolean => {
  if (!errors || errors.length === 0) return false;
  MESSAGING$.notifyRelayError({ res: { errors } });
  return true;
};
