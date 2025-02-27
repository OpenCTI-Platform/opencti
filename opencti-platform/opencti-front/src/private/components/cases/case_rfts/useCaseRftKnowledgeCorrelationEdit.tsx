import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useCaseRftKnowledgeCorrelationEditMutation } from './__generated__/useCaseRftKnowledgeCorrelationEditMutation.graphql';

const caseRftKnowledgeCorrelationEdit = graphql`
  mutation useCaseRftKnowledgeCorrelationEditMutation(
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

const useCaseRftKnowledgeCorrelationEdit = () => {
  return useApiMutation<useCaseRftKnowledgeCorrelationEditMutation>(
    caseRftKnowledgeCorrelationEdit,
  );
};

export default useCaseRftKnowledgeCorrelationEdit;
