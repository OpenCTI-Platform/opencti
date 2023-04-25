import { graphql } from 'react-relay';

export const caseRfiKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation CaseRfiKnowledgeGraphQueryCaseRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    caseRfiRelationAdd(id: $id, input: $input) {
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

export const caseRfiKnowledgeGraphMutationRelationDeleteMutation = graphql`
  mutation CaseRfiKnowledgeGraphQueryCaseRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    caseRfiRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      id
    }
  }
`;

export const caseRfiKnowledgeGraphQueryStixRelationshipDeleteMutation = graphql`
  mutation CaseRfiKnowledgeGraphQueryCaseStixRelationshipDeleteMutation($id: ID!) {
    stixRelationshipEdit(id: $id) {
      delete
    }
  }
`;

export const caseRfiKnowledgeGraphQueryStixObjectDeleteMutation = graphql`
  mutation CaseRfiKnowledgeGraphQueryCaseStixCoreObjectDeleteMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;
