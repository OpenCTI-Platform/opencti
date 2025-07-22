import { graphql, UseMutationConfig } from 'react-relay';
import { useState } from 'react';
import { useEmailTemplateDeleteMutation } from '@components/settings/email_template/__generated__/useEmailTemplateDeleteMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const emailTemplateDeleteMutation = graphql`
    mutation useEmailTemplateDeleteMutation($id: ID!) {
        emailTemplateDelete(id: $id)
    }
`;

const useEmailTemplateFormDelete = () => {
  const [mutating, setMutating] = useState(false);
  const [commitDeleteMutation] = useApiMutation<useEmailTemplateDeleteMutation>(emailTemplateDeleteMutation);

  const mutation = (
    { variables, updater, onCompleted, onError }: UseMutationConfig<useEmailTemplateDeleteMutation>,
  ) => {
    setMutating(true);
    commitDeleteMutation({
      variables,
      updater: (store, response) => {
        updater?.(store, response);
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
