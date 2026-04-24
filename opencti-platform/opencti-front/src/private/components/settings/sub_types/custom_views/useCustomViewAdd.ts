import { graphql } from 'react-relay';
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
  const [commitAddMutation] = useApiMutation<useCustomViewAdd_Mutation>(customViewAddMutation);
  const { refetchCustomViews } = useCustomViewsData();
  const mutation: typeof commitAddMutation = ({ variables, onCompleted, onError }) => {
    commitAddMutation({
      variables,
      onError: (error) => {
        onError?.(error);
      },
      onCompleted: (...args) => {
        onCompleted?.(...args);
        refetchCustomViews();
      },
    });
  };
  return mutation;
};

export default useCustomViewAdd;
