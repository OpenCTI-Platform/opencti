import { graphql } from 'react-relay';
import { useIncidentKnowledgeGraphAddRelationMutation } from './__generated__/useIncidentKnowledgeGraphAddRelationMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const incidentKnowledgeGraphAddRelationMutation = graphql`
  mutation useIncidentKnowledgeGraphAddRelationMutation(
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

const useIncidentKnowledgeGraphAddRelation = () => {
  return useApiMutation<useIncidentKnowledgeGraphAddRelationMutation>(
    incidentKnowledgeGraphAddRelationMutation,
  );
};

export default useIncidentKnowledgeGraphAddRelation;
