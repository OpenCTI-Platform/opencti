import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

interface AddRelationshipInput {
  relationship_type: string
  fromId: string
  toId: string
  createdBy: string
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

// eslint-disable-next-line import/prefer-default-export
export const addRelationship = async (
  request: APIRequestContext,
  input: AddRelationshipInput,
) => {
  return graphqlQuery(request, addRelationshipMutation(input));
};
