import { graphql } from 'react-relay';
import { useCaseRftKnowledgeGraphEditMutation } from './__generated__/useCaseRftKnowledgeGraphEditMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const caseRftKnowledgeGraphEdit = graphql`
  mutation useCaseRftKnowledgeGraphEditMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        id
      }
    }
  }
`;

const useCaseRftKnowledgeGraphEdit = () => {
  return useApiMutation<useCaseRftKnowledgeGraphEditMutation>(
    caseRftKnowledgeGraphEdit,
  );
};

export default useCaseRftKnowledgeGraphEdit;
