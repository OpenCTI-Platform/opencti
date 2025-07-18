import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNodeFromEdge } from '../../../../utils/store';

const emailTemplateAddMutation = graphql`
    mutation useEmailTemplateAddMutation($input: FintelTemplateAddInput!) {
        fintelTemplateAdd(input: $input) {
            id
            entity_type
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
          'fintelTemplates',
          'fintelTemplateAdd',
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
