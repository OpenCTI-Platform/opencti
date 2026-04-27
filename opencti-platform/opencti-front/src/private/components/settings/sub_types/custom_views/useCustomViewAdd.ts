import { graphql } from 'react-relay';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useCustomViewAdd_Mutation } from './__generated__/useCustomViewAdd_Mutation.graphql';
import { invalidateCustomViewsData } from '../../../custom_views/useCustomViewsData';

const customViewAddMutation = graphql`
  mutation useCustomViewAdd_Mutation($input: CustomViewAddInput!) {
    customViewAdd(input: $input) {
      id
    }
  }
`;

const customViewsRootArgs = (entityType: string) => ({
  entityType,
  orderBy: 'name',
  orderMode: 'asc',
});

/**
 * Hook handling Custom view creation logic
 */
const useCustomViewAdd = () => {
  const [commitAddMutation] = useApiMutation<useCustomViewAdd_Mutation>(customViewAddMutation);
  const mutation: typeof commitAddMutation = ({ variables, onCompleted, onError }) => {
    commitAddMutation({
      variables,
      updater: (store) => {
        const root = store.getRoot();
        const args = customViewsRootArgs(variables.input.targetEntityType);
        const customViewsConnection = root.getLinkedRecord('customViews', args);
        customViewsConnection?.invalidateRecord();
      },
      onError: (error) => {
        onError?.(error);
      },
      onCompleted: (...args) => {
        invalidateCustomViewsData(variables.input.targetEntityType);
        onCompleted?.(...args);
      },
    });
  };
  return mutation;
};

export default useCustomViewAdd;
