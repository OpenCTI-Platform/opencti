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

// Manifest keys the editor sets from the dashboard edition drawer (DashboardViewerPermissions). Absent = open.
export interface DashboardViewerPermissions {
  allowViewersToEditTimeFilters?: boolean;
  allowViewersToChangeVariables?: boolean;
}

const workspaceManifestQuery = (id: string) => `
  query {
    workspace(id: "${id}") {
      manifest
    }
  }
`;

const patchWorkspaceManifestMutation = (id: string, manifest: string) => `
  mutation {
    workspaceFieldPatch(id: "${id}", input: [{ key: "manifest", value: ["${manifest}"] }]) {
      id
    }
  }
`;

/**
 * Writes the viewer switches in `manifest.config`, like the switches of the edition drawer do: the current manifest
 * is read back, so the widgets stay as they are. The server keeps its own keys (variables, presets) on its side.
 */
export const setDashboardViewerPermissions = async (
  request: APIRequestContext,
  workspaceId: string,
  permissions: DashboardViewerPermissions,
) => {
  const response = await graphqlQuery(request, workspaceManifestQuery(workspaceId));
  const encoded: string | null = (await response.json()).data.workspace.manifest;
  const manifest = encoded ? JSON.parse(Buffer.from(encoded, 'base64').toString('utf-8')) : { widgets: {}, config: {} };
  const patched = { ...manifest, config: { ...(manifest.config ?? {}), ...permissions } };
  const value = Buffer.from(JSON.stringify(patched), 'utf-8').toString('base64');
  return graphqlQuery(request, patchWorkspaceManifestMutation(workspaceId, value));
};
