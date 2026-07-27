import { Disposable, GraphQLTaggedNode, IEnvironment, MutationConfig, MutationParameters, PayloadError } from 'relay-runtime';
import { useMutation, UseMutationConfig } from 'react-relay';
import { ReactNode, useCallback } from 'react';
import { MESSAGING$, relayErrorHandling } from '../../relay/environment';
import { RelayError } from '../../relay/relayTypes';
import { useDeferredCreation } from './useDeferredCreation';

export interface UsiApiMutationOptions {
  errorMessage?: string | ReactNode;
  errorMessageMap?: Record<string, string | ReactNode>;
  successMessage?: string | ReactNode;
}

/**
 * Hook wrapping Relay useMutation to automatically display an error popup with a message if the mutation fails.
 *
 * When `DeferredCreationContext.isDeferredMode` is active (e.g. a draft-only user is
 * creating an entity on the fly inside a Form Intake), the mutation is NOT dispatched
 * to the server. Instead, the raw `input` from `variables` is captured via the context
 * so it can be bundled and created in draft when the form intake is submitted.
 */
const useApiMutation = <T extends MutationParameters>(
  query: GraphQLTaggedNode,
  fn?: (environment: IEnvironment, config: MutationConfig<T>) => Disposable,
  options?: UsiApiMutationOptions,
): [(args: UseMutationConfig<T>) => void, boolean] => {
  const { isDeferredMode, captureInput } = useDeferredCreation();
  const [commit, inFlight] = useMutation(query, fn);
  const commitWithError = useCallback((args: UseMutationConfig<T>) => {
    if (isDeferredMode) {
      // Intercept the mutation: capture the raw input data and fake a successful
      // completion so the creation form closes gracefully without any server call.
      //
      // SDO mutations wrap the input: { input: { name, description, … } }
      // SCO mutations use flat top-level variables: { type: 'IPv4-Addr', IPv4Addr: { value: '…' }, … }
      const variables = args.variables as Record<string, unknown>;
      const inputData = (variables?.input as Record<string, unknown> | undefined) ?? variables;
      if (inputData) {
        captureInput(inputData);
      }
      // Suppress the success notification – the entity hasn't been created yet.
      args.onCompleted?.({} as T['response'], null);
      return;
    }
    commit({
      ...args,
      onError: (error: Error) => {
        if (args.onError) {
          args.onError(error);
          if (options?.errorMessageMap) {
            MESSAGING$.notifyCustomRelayError(error as unknown as RelayError, options.errorMessageMap);
          } else if (options?.errorMessage) {
            MESSAGING$.notifyError(options?.errorMessage);
          } else {
            MESSAGING$.notifyRelayError(error as unknown as RelayError);
          }
        } else relayErrorHandling(error);
      },
      onCompleted: (response: T['response'], errors: PayloadError[] | null) => {
        if (args.onCompleted) args.onCompleted(response, errors);
        if (options?.successMessage) MESSAGING$.notifySuccess(options.successMessage);
      },
    });
  }, [commit, isDeferredMode, captureInput]);
  return [commitWithError, inFlight];
};

export default useApiMutation;
