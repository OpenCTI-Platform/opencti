import { graphql } from 'react-relay';
import { useState } from 'react';
import { useEmailTemplateEditMutation } from '@components/settings/email_template/__generated__/useEmailTemplateEditMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const emailTemplateEditMutation = graphql`
    mutation useEmailTemplateEditMutation($id: ID!, $input: [EditInput!]!) {
        emailTemplateFieldPatch(id: $id, input: $input) {
            id
            entity_type
            ...EmailTemplateTabs_template
            ...EmailTemplateHeader_template
        }
    }
`;

const useEmailTemplateEdit = () => {
  const [mutating, setMutating] = useState(false);
  const [commitEditMutation] = useApiMutation<useEmailTemplateEditMutation>(emailTemplateEditMutation);

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
      },
    });
  };

  return [mutation, mutating] as const;
};

export default useEmailTemplateEdit;
