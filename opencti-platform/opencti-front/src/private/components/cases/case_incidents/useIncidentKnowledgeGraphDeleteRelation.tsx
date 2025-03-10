import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useIncidentKnowledgeGraphDeleteRelationMutation } from './__generated__/useIncidentKnowledgeGraphDeleteRelationMutation.graphql';

const incidentKnowledgeGraphDeleteRelation = graphql`
  mutation useIncidentKnowledgeGraphDeleteRelationMutation(
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

const useIncidentKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useIncidentKnowledgeGraphDeleteRelationMutation>(
    incidentKnowledgeGraphDeleteRelation,
  );
};

export default useIncidentKnowledgeGraphDeleteRelation;
