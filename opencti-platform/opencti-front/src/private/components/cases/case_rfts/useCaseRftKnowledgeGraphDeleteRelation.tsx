import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useCaseRftKnowledgeGraphDeleteRelationMutation } from './__generated__/useCaseRftKnowledgeGraphDeleteRelationMutation.graphql';

const caseRftKnowledgeGraphDeleteRelation = graphql`
  mutation useCaseRftKnowledgeGraphDeleteRelationMutation(
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

const useCaseRftKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useCaseRftKnowledgeGraphDeleteRelationMutation>(
    caseRftKnowledgeGraphDeleteRelation,
  );
};

export default useCaseRftKnowledgeGraphDeleteRelation;
