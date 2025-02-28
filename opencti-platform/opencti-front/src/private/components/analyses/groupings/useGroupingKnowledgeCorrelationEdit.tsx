import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useGroupingKnowledgeCorrelationEditMutation } from './__generated__/useGroupingKnowledgeCorrelationEditMutation.graphql';

const groupingKnowledgeCorrelationEdit = graphql`
  mutation useGroupingKnowledgeCorrelationEditMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    groupingFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      id
    }
  }
`;

const useGroupingKnowledgeCorrelationEdit = () => {
  return useApiMutation<useGroupingKnowledgeCorrelationEditMutation>(
    groupingKnowledgeCorrelationEdit,
  );
};

export default useGroupingKnowledgeCorrelationEdit;
