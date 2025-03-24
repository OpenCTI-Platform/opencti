import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useGroupingKnowledgeGraphDeleteRelationMutation } from './__generated__/useGroupingKnowledgeGraphDeleteRelationMutation.graphql';

const groupingKnowledgeGraphDeleteRelation = graphql`
  mutation useGroupingKnowledgeGraphDeleteRelationMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupingRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      id
    }
  }
`;

const useGroupingKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useGroupingKnowledgeGraphDeleteRelationMutation>(
    groupingKnowledgeGraphDeleteRelation,
  );
};

export default useGroupingKnowledgeGraphDeleteRelation;
