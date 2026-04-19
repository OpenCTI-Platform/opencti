import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { customViewsDisplayContextUpdater } from './store-updaters';
import type { useCustomViewDuplicate_Mutation } from './__generated__/useCustomViewDuplicate_Mutation.graphql';

const duplicateMutation = graphql`
  mutation useCustomViewDuplicate_Mutation(
    $input: CustomViewDuplicateInput!
  ) {
    customViewDuplicate(input: $input) {
      id
      targetEntityType
    }
  }
`;

/**
 * Hook handling Custom view duplication logic
 */
const useCustomViewDuplicate = () => {
  const [mutating, setMutating] = useState(false);
  const [commitDuplicateMutation] = useApiMutation<useCustomViewDuplicate_Mutation>(duplicateMutation);

  const mutation: typeof commitDuplicateMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitDuplicateMutation({
      variables,
      updater: customViewsDisplayContextUpdater,
      onError: (error) => {
        setMutating(false);
        onError?.(error);
      },
      onCompleted: (...args) => {
        setMutating(false);
        onCompleted?.(...args);
      },
    });
  };

  return [mutation, mutating] as const;
};

export default useCustomViewDuplicate;
