import { graphql } from 'react-relay';
import { useReportKnowledgeGraphAddRelationMutation } from './__generated__/useReportKnowledgeGraphAddRelationMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const reportKnowledgeGraphAddRelationMutation = graphql`
  mutation useReportKnowledgeGraphAddRelationMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input, commitMessage: $commitMessage, references: $references) {
        id
        entity_type
        parent_types
        to {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
        }
      }
    }
  }
`;

const useReportKnowledgeGraphAddRelation = () => {
  return useApiMutation<useReportKnowledgeGraphAddRelationMutation>(
    reportKnowledgeGraphAddRelationMutation,
  );
};

export default useReportKnowledgeGraphAddRelation;
