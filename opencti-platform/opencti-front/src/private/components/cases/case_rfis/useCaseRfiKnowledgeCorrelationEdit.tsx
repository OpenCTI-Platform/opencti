import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useCaseRfiKnowledgeCorrelationEditMutation } from './__generated__/useCaseRfiKnowledgeCorrelationEditMutation.graphql';

const caseRfiKnowledgeCorrelationEdit = graphql`
  mutation useCaseRfiKnowledgeCorrelationEditMutation(
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

const useCaseRfiKnowledgeCorrelationEdit = () => {
  return useApiMutation<useCaseRfiKnowledgeCorrelationEditMutation>(
    caseRfiKnowledgeCorrelationEdit,
  );
};

export default useCaseRfiKnowledgeCorrelationEdit;
