import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useInvestigationGraphDeleteRelationMutation } from './__generated__/useInvestigationGraphDeleteRelationMutation.graphql';

const investigationGraphDeleteRelationMutation = graphql`
  mutation useInvestigationGraphDeleteRelationMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const useInvestigationGraphDeleteRelation = () => {
  return useApiMutation<useInvestigationGraphDeleteRelationMutation>(
    investigationGraphDeleteRelationMutation,
  );
};

export default useInvestigationGraphDeleteRelation;
