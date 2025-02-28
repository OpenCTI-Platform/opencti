import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useInvestigationGraphAddRelationMutation } from './__generated__/useInvestigationGraphAddRelationMutation.graphql';

const investigationGraphAddRelationMutation = graphql`
  mutation useInvestigationGraphAddRelationMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const useInvestigationGraphAddRelation = () => {
  return useApiMutation<useInvestigationGraphAddRelationMutation>(
    investigationGraphAddRelationMutation,
  );
};

export default useInvestigationGraphAddRelation;
