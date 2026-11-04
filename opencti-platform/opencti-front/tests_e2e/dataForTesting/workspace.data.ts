import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const addDashboardMutation = (name: string) => `
  mutation {
    workspaceAdd(input: { type: "dashboard", name: "${name}" }) {
      id
    }
  }
`;

export const addDashboard = async (
  request: APIRequestContext,
  name: string,
) => {
  return graphqlQuery(request, addDashboardMutation(name));
};

interface UpsertEntityVariableInput {
  id: string;
  name: string;
  entityTypes: string[];
  defaultValue: string;
}

// Same payload as the variable dialog: an entity variable with no restriction.
const upsertEntityVariableMutation = (workspaceId: string, input: UpsertEntityVariableInput) => `
  mutation {
    workspaceVariableUpsert(id: "${workspaceId}", input: {
      id: "${input.id}",
      name: "${input.name}",
      type: entity,
      entityTypes: [${input.entityTypes.map((type) => `"${type}"`).join(', ')}],
      restriction: { mode: none },
      defaultValue: "${input.defaultValue}"
    }) {
      id
    }
  }
`;

export const upsertEntityVariable = async (
  request: APIRequestContext,
  workspaceId: string,
  input: UpsertEntityVariableInput,
) => {
  return graphqlQuery(request, upsertEntityVariableMutation(workspaceId, input));
};

const deleteWorkspaceMutation = (id: string) => `
  mutation {
    workspaceDelete(id: "${id}")
  }
`;

export const deleteWorkspace = async (
  request: APIRequestContext,
  id: string,
) => {
  return graphqlQuery(request, deleteWorkspaceMutation(id));
};
