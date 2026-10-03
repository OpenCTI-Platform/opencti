import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const settingsQuery = () => `
  query {
    settings {
      id
      platform_theme {
        id
        name
      }
    }
  }
`;

export const getSettings = async (request: APIRequestContext) => {
  const response = await graphqlQuery(request, settingsQuery());
  const data = await response.json();
  const settings = data.data?.settings;
  if (!settings?.id) {
    throw new Error(`Cannot fetch platform settings: ${JSON.stringify(data.errors ?? data)}`);
  }
  return settings;
};

const patchSettingsMutation = (id: string, key: string, value: string) => `
  mutation {
    settingsEdit(id: "${id}") {
      fieldPatch(input: [{ key: "${key}", value: "${value}" }]) {
        id
      }
    }
  }
`;

/**
 * Set an explicit value on the platform settings (idempotent, unlike UI
 * interactions which depend on the current state).
 */
export const patchSettings = async (
  request: APIRequestContext,
  settingsId: string,
  key: string,
  value: string,
) => {
  const response = await graphqlQuery(request, patchSettingsMutation(settingsId, key, value));
  const data = await response.json();
  if (data.errors || !data.data?.settingsEdit?.fieldPatch) {
    throw new Error(`Cannot patch settings ${key}: ${JSON.stringify(data.errors ?? data)}`);
  }
  return data;
};

const themesQuery = (search: string) => `
  query {
    themes(search: "${search}") {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

export const getThemeIdByName = async (request: APIRequestContext, name: string) => {
  const response = await graphqlQuery(request, themesQuery(name));
  const data = await response.json();
  const edges = data.data?.themes?.edges ?? [];
  const theme = edges.map((e: { node: { id: string; name: string } }) => e.node)
    .find((node: { id: string; name: string }) => node.name === name);
  if (!theme) {
    throw new Error(`Cannot find theme named ${name}: ${JSON.stringify(data.errors ?? data)}`);
  }
  return theme.id;
};
