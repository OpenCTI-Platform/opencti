import { graphql } from 'react-relay';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFintelTemplateEditMutation, useFintelTemplateEditMutation$variables } from './__generated__/useFintelTemplateEditMutation.graphql';

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
  const [commitEditMutation] = useApiMutation<useFintelTemplateEditMutation>(fintelTemplateEditMutation);

  return (variables: useFintelTemplateEditMutation$variables) => {
    commitEditMutation({ variables });
  };
};

export default useFintelTemplateEdit;
