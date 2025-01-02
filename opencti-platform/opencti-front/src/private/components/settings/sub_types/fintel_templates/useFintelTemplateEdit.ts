import { graphql } from 'react-relay';
import { useState } from 'react';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFintelTemplateEditMutation } from './__generated__/useFintelTemplateEditMutation.graphql';

const fintelTemplateEditMutation = graphql`
  mutation useFintelTemplateEditMutation($id: ID!, $input: [EditInput!]!) {
    fintelTemplateFieldPatch(id: $id, input: $input) {
      id
      name
      description
      instance_filters
      settings_types
      start_date
      entity_type
      content
    }
  }
`;

const useFintelTemplateEdit = () => {
  const [mutating, setMutating] = useState(false);
  const [commitEditMutation] = useApiMutation<useFintelTemplateEditMutation>(fintelTemplateEditMutation);

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

export default useFintelTemplateEdit;
