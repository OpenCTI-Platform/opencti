import { useMutation } from 'react-relay';
import type { GraphQLTaggedNode, MutationParameters, PayloadError } from 'relay-runtime';
import { MESSAGING$ } from '../../../relay/environment';
import type { RelayError } from '../../../relay/relayTypes';

/**
 * A mutation whose errors a design-system dialog shows in its own body. Unlike useApiMutation, it raises no global
 * snackbar: the snackbar renders under the overlay of the dialog, then repeats the error once the dialog closes.
 */
export const useDialogMutation = <T extends MutationParameters>(mutation: GraphQLTaggedNode) => useMutation<T>(mutation);

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

/**
 * The message of GraphQL payload errors, for a dialog to show in its own body: the global snackbar renders under the
 * overlay of a design-system dialog.
 */
export const payloadErrorsMessage = (errors: readonly PayloadError[] | null | undefined): string | null => {
  const messages = (errors ?? []).map((error) => error.message).filter((message) => !!message);
  return messages.length > 0 ? messages.join(' ') : null;
};

/** The message of a failed mutation (onError), for a dialog to show in its own body. */
export const mutationErrorMessage = (error: Error, fallback: string): string => {
  const messages = ((error as unknown as Partial<RelayError>).res?.errors ?? [])
    .map((relayError) => relayError.message)
    .filter((message): message is string => !!message);
  return messages.length > 0 ? messages.join(' ') : fallback;
};
