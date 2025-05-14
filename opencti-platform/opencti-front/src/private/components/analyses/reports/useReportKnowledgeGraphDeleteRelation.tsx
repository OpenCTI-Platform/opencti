import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useReportKnowledgeGraphDeleteRelationMutation } from './__generated__/useReportKnowledgeGraphDeleteRelationMutation.graphql';

const reportKnowledgeGraphDeleteRelation = graphql`
  mutation useReportKnowledgeGraphDeleteRelationMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    reportEdit(id: $id) {
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
        commitMessage: $commitMessage
        references: $references
      ) {
        id
      }
    }
  }
`;

const useReportKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useReportKnowledgeGraphDeleteRelationMutation>(
    reportKnowledgeGraphDeleteRelation,
  );
};

export default useReportKnowledgeGraphDeleteRelation;
