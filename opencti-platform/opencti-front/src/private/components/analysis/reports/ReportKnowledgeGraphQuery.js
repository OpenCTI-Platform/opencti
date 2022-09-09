import { graphql } from 'react-relay';

export const reportKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation ReportKnowledgeGraphQueryRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    reportEdit(id: $id) {
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

export const reportKnowledgeGraphMutationRelationDeleteMutation = graphql`
  mutation ReportKnowledgeGraphQueryRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    reportEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

export const reportKnowledgeGraphQueryStixRelationshipDeleteMutation = graphql`
  mutation ReportKnowledgeGraphQueryStixRelationshipDeleteMutation($id: ID!) {
    stixRelationshipEdit(id: $id) {
      delete
    }
  }
`;
