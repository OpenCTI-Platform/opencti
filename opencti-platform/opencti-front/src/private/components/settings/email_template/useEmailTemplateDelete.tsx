import { graphql, UseMutationConfig } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNodeFromEdge } from '../../../../utils/store';

const emailTemplateDeleteMutation = graphql`
    mutation useEmailTemplateDeleteMutation($id: ID!) {
        fintelTemplateDelete(id: $id)
    }
`;

const useEmailTemplateFormDelete = (entitySettingId: string) => {
  const [mutating, setMutating] = useState(false);
  const [commitDeleteMutation] = useApiMutation<useEmailTemplateDeleteMutation>(emailTemplateDeleteMutation);

  const mutation = (
    id:string,
    { variables, onCompleted, onError }: UseMutationConfig<useEmailTemplateDeleteMutation>,
  ) => {
    setMutating(true);
    commitDeleteMutation({
      variables,
      updater: (store) => {
        deleteNodeFromEdge(
          store,
          'emailTemplates',
          entitySettingId,
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

export default useEmailTemplateFormDelete;
