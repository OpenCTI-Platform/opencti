import { graphql } from 'react-relay';
import { useCaseRftKnowledgeGraphAddRelationMutation } from './__generated__/useCaseRftKnowledgeGraphAddRelationMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const caseRftKnowledgeGraphAddRelationMutation = graphql`
  mutation useCaseRftKnowledgeGraphAddRelationMutation(
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

const useCaseRftKnowledgeGraphAddRelation = () => {
  return useApiMutation<useCaseRftKnowledgeGraphAddRelationMutation>(
    caseRftKnowledgeGraphAddRelationMutation,
  );
};

export default useCaseRftKnowledgeGraphAddRelation;
