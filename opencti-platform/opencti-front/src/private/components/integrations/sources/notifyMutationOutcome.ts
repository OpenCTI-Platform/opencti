import type { PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../../relay/environment';

interface MutationOutcomeMessages {
  success?: string | null;
  failure?: string | null;
}

/**
 * `useApiMutation` hands GraphQL payload errors to `onCompleted` and its own success message is unconditional:
 * Source Intelligence mutations report their outcome here instead and only continue when it is a success.
 * `failure` reports a mutation that resolved without errors but did not do what was asked.
 */
const notifyMutationOutcome = (errors: readonly PayloadError[] | null | undefined, messages: MutationOutcomeMessages = {}): boolean => {
  if (errors && errors.length > 0) {
    MESSAGING$.notifyError(errors.map((error) => error.message).join(' - '));
    return false;
  }
  if (messages.failure) {
    MESSAGING$.notifyError(messages.failure);
    return false;
  }
  if (messages.success) {
    MESSAGING$.notifySuccess(messages.success);
  }
  return true;
};

export default notifyMutationOutcome;
