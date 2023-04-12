import { graphql } from 'react-relay';

export const groupingKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation GroupingKnowledgeGraphQueryRelationAddMutation(
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

export const groupingKnowledgeGraphMutationRelationDeleteMutation = graphql`
  mutation GroupingKnowledgeGraphQueryRelationDeleteMutation(
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

export const groupingKnowledgeGraphQueryStixRelationshipDeleteMutation = graphql`
  mutation GroupingKnowledgeGraphQueryStixRelationshipDeleteMutation($id: ID!) {
    stixRelationshipEdit(id: $id) {
      delete
    }
  }
`;
