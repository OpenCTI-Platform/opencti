import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

interface AddLabelInput {
  value: string;
}

const addLabelMutation = (input: AddLabelInput) => `
  mutation {
    labelAdd(input: {
      value: "${input.value}"
    }) {
      id
    }
  }
`;

export const addLabel = async (
  request: APIRequestContext,
  input: AddLabelInput,
) => {
  return graphqlQuery(request, addLabelMutation(input));
};

const deleteLabelMutation = (id: string) => `
  mutation {
    labelEdit(id: "${id}") {
      delete
    }
  }
`;

export const deleteLabel = async (
  request: APIRequestContext,
  id: string,
) => {
  return graphqlQuery(request, deleteLabelMutation(id));
};
