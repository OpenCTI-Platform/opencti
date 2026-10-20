import { createServer, type Server } from 'node:net';
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

// A localhost port only one process can listen on: the operating system frees it when its holder
// exits, killed or not, so the lock never outlives its holder and is never taken over.
const PLATFORM_THEME_LOCK_PORT = 47813;
const PLATFORM_THEME_LOCK_RETRY_MS = 250;

const listenOnLockPort = () => new Promise<Server | null>((resolve, reject) => {
  const server = createServer();
  server.once('error', (error) => {
    if ((error as { code?: string }).code === 'EADDRINUSE') resolve(null);
    else reject(error);
  });
  server.listen(PLATFORM_THEME_LOCK_PORT, '127.0.0.1', () => resolve(server));
});

/**
 * Waits until no other test file holds the platform theme, takes it, and returns the function
 * that gives it back. The platform theme colours every page of every test: each test that changes
 * it, or that compares screenshots, holds it for its own run (never a whole suite, so a waiting
 * test is never kept beyond its timeout) and local runs, which execute several files at once,
 * never overlap them.
 */
export const acquirePlatformThemeLock = async (): Promise<() => Promise<void>> => {
  const server = await listenOnLockPort();
  if (!server) {
    await new Promise((resolve) => {
      setTimeout(resolve, PLATFORM_THEME_LOCK_RETRY_MS);
    });
    return acquirePlatformThemeLock();
  }
  // Held, the lock never keeps a worker alive on its own.
  server.unref();
  return () => new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
};
