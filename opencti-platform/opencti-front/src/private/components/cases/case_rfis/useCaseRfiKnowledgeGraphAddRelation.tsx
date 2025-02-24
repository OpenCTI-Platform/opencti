import { graphql } from 'react-relay';
import { useCaseRfiKnowledgeGraphAddRelationMutation } from './__generated__/useCaseRfiKnowledgeGraphAddRelationMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const caseRfiKnowledgeGraphAddRelationMutation = graphql`
  mutation useCaseRfiKnowledgeGraphAddRelationMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
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

const useCaseRfiKnowledgeGraphAddRelation = () => {
  return useApiMutation<useCaseRfiKnowledgeGraphAddRelationMutation>(
    caseRfiKnowledgeGraphAddRelationMutation,
  );
};

export default useCaseRfiKnowledgeGraphAddRelation;
