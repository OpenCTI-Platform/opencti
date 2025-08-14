import { graphql } from 'react-relay';
import { useState } from 'react';
import { useEmailTemplateAddMutation } from '@components/settings/email_template/__generated__/useEmailTemplateAddMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const emailTemplateAddMutation = graphql`
    mutation useEmailTemplateAddMutation($input: EmailTemplateAddInput!) {
        emailTemplateAdd(input: $input) {
            id
            entity_type
        }
    }
`;

const useEmailTemplateAdd = () => {
  const [mutating, setMutating] = useState(false);
  const [commitAddMutation] = useApiMutation<useEmailTemplateAddMutation>(emailTemplateAddMutation);

  const mutation: typeof commitAddMutation = ({ variables, updater, onCompleted, onError }) => {
    setMutating(true);
    commitAddMutation({
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

export default useEmailTemplateAdd;
