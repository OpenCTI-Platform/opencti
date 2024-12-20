import { graphql, UseMutationConfig } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFintelTemplateDeleteMutation } from './__generated__/useFintelTemplateDeleteMutation.graphql';
import { deleteNodeFromEdge } from '../../../../../utils/store';

const fintelTemplateDeleteMutation = graphql`
  mutation useFintelTemplateDeleteMutation($id: ID!) {
    fintelTemplateDelete(id: $id)
  }
`;

const useFintelTemplateFormDelete = (entitySettingId: string) => {
  const [mutating, setMutating] = useState(false);
  const [commitDeleteMutation] = useApiMutation<useFintelTemplateDeleteMutation>(fintelTemplateDeleteMutation);

  const mutation = (
    id:string,
    { variables, onCompleted, onError }: UseMutationConfig<useFintelTemplateDeleteMutation>,
  ) => {
    setMutating(true);
    commitDeleteMutation({
      variables,
      updater: (store) => {
        deleteNodeFromEdge(
          store,
          'fintelTemplates',
          entitySettingId,
          id,
        );
      },
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

export default useFintelTemplateFormDelete;
