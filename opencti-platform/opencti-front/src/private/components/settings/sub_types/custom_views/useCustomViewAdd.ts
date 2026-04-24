import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useCustomViewAdd_Mutation } from './__generated__/useCustomViewAdd_Mutation.graphql';
import { useCustomViewsData } from '../../../custom_views/useCustomViewsData';

const customViewAddMutation = graphql`
  mutation useCustomViewAdd_Mutation($input: CustomViewAddInput!) {
    customViewAdd(input: $input) {
      id
    }
  }
`;

/**
 * Hook handling Custom view creation logic
 */
const useCustomViewAdd = () => {
  const [mutating, setMutating] = useState(false);
  const [commitAddMutation] = useApiMutation<useCustomViewAdd_Mutation>(customViewAddMutation);
  const { refetchCustomViews } = useCustomViewsData();

  const mutation: typeof commitAddMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitAddMutation({
      variables,
      onError: (error) => {
        setMutating(false);
        onError?.(error);
      },
      onCompleted: (...args) => {
        setMutating(false);
        onCompleted?.(...args);
        refetchCustomViews();
      },
    });
  };

  return [mutation, mutating] as const;
};

export default useCustomViewAdd;
