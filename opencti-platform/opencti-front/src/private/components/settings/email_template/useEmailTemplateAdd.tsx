import { graphql } from 'react-relay';
import { useState } from 'react';
import { useEmailTemplateAddMutation } from '@components/settings/email_template/__generated__/useEmailTemplateAddMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNodeFromEdge } from '../../../../utils/store';

const emailTemplateAddMutation = graphql`
    mutation useEmailTemplateAddMutation($input: EmailTemplateAddInput!) {
        emailTemplateAdd(input: $input) {
            id
            entity_type
            name
            description
            email_object
            sender_email
            template_body
        }
    }
`;

const useEmailTemplateAdd = () => {
  const [mutating, setMutating] = useState(false);
  const [commitAddMutation] = useApiMutation<useEmailTemplateAddMutation>(emailTemplateAddMutation);

  const mutation: typeof commitAddMutation = ({ variables, onCompleted, onError }) => {
    setMutating(true);
    commitAddMutation({
      variables,
      updater: (store) => {
        insertNodeFromEdge(
          store,
          'emailTemplates',
          'emailTemplatesAdd',
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

export default useEmailTemplateAdd;
