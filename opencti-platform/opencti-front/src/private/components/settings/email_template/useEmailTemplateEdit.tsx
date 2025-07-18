import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const emailTemplateEditMutation = graphql`
    mutation useEmailTemplateEditMutation($id: ID!, $input: [EditInput!]!) {
        fintelTemplateFieldPatch(id: $id, input: $input) {
            id
            name
            description
            instance_filters
            settings_types
            start_date
            ...FintelTemplateTabs_template
            ...FintelTemplateWidgetsSidebar_template
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
