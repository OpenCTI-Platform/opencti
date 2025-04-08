import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useInvestigationGraphEditMutation } from './__generated__/useInvestigationGraphEditMutation.graphql';

const investigationGraphEdit = graphql`
  mutation useInvestigationGraphEditMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const useInvestigationGraphEdit = () => {
  return useApiMutation<useInvestigationGraphEditMutation>(
    investigationGraphEdit,
  );
};

export default useInvestigationGraphEdit;
