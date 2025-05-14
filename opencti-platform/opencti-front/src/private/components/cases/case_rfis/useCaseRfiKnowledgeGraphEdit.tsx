import { graphql } from 'react-relay';
import { useCaseRfiKnowledgeGraphEditMutation } from './__generated__/useCaseRfiKnowledgeGraphEditMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const caseRfiKnowledgeGraphEdit = graphql`
  mutation useCaseRfiKnowledgeGraphEditMutation(
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

const useCaseRfiKnowledgeGraphEdit = () => {
  return useApiMutation<useCaseRfiKnowledgeGraphEditMutation>(
    caseRfiKnowledgeGraphEdit,
  );
};

export default useCaseRfiKnowledgeGraphEdit;
