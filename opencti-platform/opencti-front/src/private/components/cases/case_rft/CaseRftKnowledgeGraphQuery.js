import { graphql } from 'react-relay';

export const caseRftKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation CaseRftKnowledgeGraphQueryCaseRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    caseRftRelationAdd(id: $id, input: $input) {
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

export const caseRftKnowledgeGraphMutationRelationDeleteMutation = graphql`
  mutation CaseRftKnowledgeGraphQueryCaseRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    caseRftRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      id
    }
  }
`;

export const caseRftKnowledgeGraphQueryStixRelationshipDeleteMutation = graphql`
  mutation CaseRftKnowledgeGraphQueryCaseStixRelationshipDeleteMutation($id: ID!) {
    stixRelationshipEdit(id: $id) {
      delete
    }
  }
`;

export const caseRftKnowledgeGraphQueryStixObjectDeleteMutation = graphql`
  mutation CaseRftKnowledgeGraphQueryCaseStixCoreObjectDeleteMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;
