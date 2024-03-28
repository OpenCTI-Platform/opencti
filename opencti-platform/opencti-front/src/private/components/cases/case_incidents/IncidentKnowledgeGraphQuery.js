import { graphql } from 'react-relay';

export const incidentKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation IncidentKnowledgeGraphQueryCaseRelationAddMutation(
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

export const incidentKnowledgeGraphMutationRelationDeleteMutation = graphql`
  mutation IncidentKnowledgeGraphQueryCaseRelationDeleteMutation(
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
