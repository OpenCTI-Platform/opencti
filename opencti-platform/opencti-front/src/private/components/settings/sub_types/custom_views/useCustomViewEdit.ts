import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useCustomViewEdit_Mutation } from './__generated__/useCustomViewEdit_Mutation.graphql';
import { useCustomViewsData } from '@components/custom_views/useCustomViewsData';

const customViewEditMutation = graphql`
  mutation useCustomViewEdit_Mutation($id: ID!, $input: [EditInput!]!) {
    customViewEdit(id: $id, input: $input) {
      id
      name
      description
      path
      enabled
      default
    }
  }
`;

/**
 * Hook handling Custom view edition.
 * To edit dashboard-related content use useCustomViewDashboardEdit.
 */
const useCustomViewEdit = () => {
  const [mutating, setMutating] = useState(false);
  const [commitEditMutation] = useApiMutation<useCustomViewEdit_Mutation>(customViewEditMutation);
  const { refetchCustomViews } = useCustomViewsData();

  const mutation: typeof commitEditMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitEditMutation({
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

export default useCustomViewEdit;
