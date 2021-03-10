import graphql from 'babel-plugin-relay/macro';

export const reportKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation ReportKnowledgeGraphQueryRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on BasicObject {
            id
            entity_type
          }
          ... on BasicRelationship {
            id
            entity_type
          }
        }
      }
    }
  }
`;

export const reportKnowledgeGraphtMutationRelationDeleteMutation = graphql`
  mutation ReportKnowledgeGraphQueryRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    reportEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;
