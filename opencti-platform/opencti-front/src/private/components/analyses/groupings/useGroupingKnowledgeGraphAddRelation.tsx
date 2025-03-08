import { graphql } from 'react-relay';
import { useGroupingKnowledgeGraphAddRelationMutation } from '@components/analyses/groupings/__generated__/useGroupingKnowledgeGraphAddRelationMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const groupingKnowledgeGraphAddRelationMutation = graphql`
  mutation useGroupingKnowledgeGraphAddRelationMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    groupingRelationAdd(id: $id, input: $input) {
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
`;

const useGroupingKnowledgeGraphAddRelation = () => {
  return useApiMutation<useGroupingKnowledgeGraphAddRelationMutation>(
    groupingKnowledgeGraphAddRelationMutation,
  );
};

export default useGroupingKnowledgeGraphAddRelation;
