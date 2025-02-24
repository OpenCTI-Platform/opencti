import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useCaseRfiKnowledgeGraphDeleteRelationMutation } from './__generated__/useCaseRfiKnowledgeGraphDeleteRelationMutation.graphql';

const caseRfiKnowledgeGraphDeleteRelation = graphql`
  mutation useCaseRfiKnowledgeGraphDeleteRelationMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
      ) {
        id
      }
    }
  }
`;

const useCaseRfiKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useCaseRfiKnowledgeGraphDeleteRelationMutation>(
    caseRfiKnowledgeGraphDeleteRelation,
  );
};

export default useCaseRfiKnowledgeGraphDeleteRelation;
