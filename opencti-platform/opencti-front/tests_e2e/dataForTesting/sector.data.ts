import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

interface AddSectorInput {
  name: string;
}

const addSectorMutation = (input: AddSectorInput) => `
  mutation {
    sectorAdd(input: {
      name: "${input.name}"
    }) {
      id
    }
  }
`;

export const addSector = async (
  request: APIRequestContext,
  input: AddSectorInput,
) => {
  return graphqlQuery(request, addSectorMutation(input));
};

const deleteSectorMutation = (id: string) => `
  mutation {
    sectorEdit(id: "${id}") {
      delete
    }
  }
`;

export const deleteSector = async (
  request: APIRequestContext,
  id: string,
) => {
  return graphqlQuery(request, deleteSectorMutation(id));
};
