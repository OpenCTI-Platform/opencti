import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useInvestigationGraphUpdateEntitiesMutation } from './__generated__/useInvestigationGraphUpdateEntitiesMutation.graphql';

const investigationGraphUpdateEntitiesMutation = graphql`
  mutation useInvestigationGraphUpdateEntitiesMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const useInvestigationGraphUpdateEntities = () => {
  return useApiMutation<useInvestigationGraphUpdateEntitiesMutation>(
    investigationGraphUpdateEntitiesMutation,
  );
};

export default useInvestigationGraphUpdateEntities;
