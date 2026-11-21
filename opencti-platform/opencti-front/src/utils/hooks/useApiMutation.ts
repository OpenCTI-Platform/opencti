import { Disposable, getRequest, GraphQLTaggedNode, IEnvironment, MutationConfig, MutationParameters, PayloadError } from 'relay-runtime';
import { useMutation, UseMutationConfig } from 'react-relay';
import { ReactNode, useCallback } from 'react';
import { MESSAGING$, relayErrorHandling } from '../../relay/environment';
import { RelayError } from '../../relay/relayTypes';
import { useDeferredCreation } from './useDeferredCreation';

// A creation mutation has a `<type>Add` root field. The other mutations a creation dialog can send (e.g. Ask AI) are not deferred.
const isCreationMutation = (query: GraphQLTaggedNode) => {
  const [root] = getRequest(query).operation.selections;
  return root !== undefined && 'name' in root && root.name.endsWith('Add');
};

export interface UsiApiMutationOptions {
  errorMessage?: string | ReactNode;
  errorMessageMap?: Record<string, string | ReactNode>;
  successMessage?: string | ReactNode;
}

/**
 * Hook wrapping Relay useMutation to automatically display an error popup with a message if the mutation fails.
 *
 * When `DeferredCreationContext.isDeferredMode` is active (an entity created on the fly
 * inside a Form Intake), a creation mutation (`<type>Add`) is NOT dispatched to the server.
 * Instead, the raw `input` from `variables` is captured via the context so it can be
 * created with the form intake submission. The other mutations are sent as usual.
 */
const useApiMutation = <T extends MutationParameters>(
  query: GraphQLTaggedNode,
  fn?: (environment: IEnvironment, config: MutationConfig<T>) => Disposable,
  options?: UsiApiMutationOptions,
): [(args: UseMutationConfig<T>) => void, boolean] => {
  const { isDeferredMode, captureInput } = useDeferredCreation();
  const [commit, inFlight] = useMutation(query, fn);
  const commitWithError = useCallback((args: UseMutationConfig<T>) => {
    if (isDeferredMode && isCreationMutation(query)) {
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
  }, [commit, query, isDeferredMode, captureInput]);
  return [commitWithError, inFlight];
};

export default useApiMutation;
