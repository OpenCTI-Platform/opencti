import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

interface AddRelationshipInput {
  relationship_type: string;
  fromId: string;
  toId: string;
  createdBy: string;
}

const addRelationshipMutation = (input: AddRelationshipInput) => `
  mutation {
    stixCoreRelationshipAdd(input: {
      relationship_type: "${input.relationship_type}",
      fromId: "${input.fromId}",
      toId: "${input.toId}",
      createdBy: "${input.createdBy}",
    }) {
      id
    }
  }
`;

export const addRelationship = async (
  request: APIRequestContext,
  input: AddRelationshipInput,
) => {
  return graphqlQuery(request, addRelationshipMutation(input));
};

interface DeleteRelationshipInput {
  relationship_type: string;
  fromId: string;
  toId: string;
}

const deleteRelationshipMutation = (input: DeleteRelationshipInput) => `
  mutation {
    stixCoreRelationshipDelete(
      fromId: "${input.fromId}"
      toId: "${input.toId}"
      relationship_type: "${input.relationship_type}"
    )
  }
`;

export const deleteRelationship = async (
  request: APIRequestContext,
  input: DeleteRelationshipInput,
) => {
  return graphqlQuery(request, deleteRelationshipMutation(input));
};
