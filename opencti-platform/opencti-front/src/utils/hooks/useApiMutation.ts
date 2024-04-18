import { Disposable, GraphQLTaggedNode, IEnvironment, MutationConfig, MutationParameters } from 'relay-runtime';
import { useMutation, UseMutationConfig } from 'react-relay';
import { useCallback } from 'react';
import { relayErrorHandling } from '../../relay/environment';

/**
 * Hook wrapping Relay useMutation to automatically display an error popup with a message if the mutation fails
 */
const useApiMutation = <T extends MutationParameters>(
  query: GraphQLTaggedNode,
  fn?: (environment: IEnvironment, config: MutationConfig<T>) => Disposable,
) => {
  const [commit] = useMutation(query, fn);
  const commitWithError = useCallback((args: UseMutationConfig<T>) => {
    commit({ ...args, onError: args.onError ?? relayErrorHandling as UseMutationConfig<T>['onError'] });
  }, [commit]);
  return [commitWithError];
};

export default useApiMutation;
