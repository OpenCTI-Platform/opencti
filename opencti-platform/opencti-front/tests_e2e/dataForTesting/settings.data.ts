import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

const PLATFORM_THEME_LOCK = join(tmpdir(), 'opencti-e2e-platform-theme.lock');
const PLATFORM_THEME_LOCK_OWNER = join(PLATFORM_THEME_LOCK, 'owner');
// The holder renews its lease this often, however long it holds the lock.
const PLATFORM_THEME_LOCK_HEARTBEAT_MS = 5 * 1000;
// A lease not renewed for this long belongs to a run that was killed.
const PLATFORM_THEME_LOCK_STALE_MS = 60 * 1000;
const PLATFORM_THEME_LOCK_RETRY_MS = 250;

const takePlatformThemeLock = async (owner: string): Promise<void> => {
  try {
    await mkdir(PLATFORM_THEME_LOCK);
    await writeFile(PLATFORM_THEME_LOCK_OWNER, owner);
  } catch (error) {
    if ((error as { code?: string }).code !== 'EEXIST') throw error;
    const age = await stat(PLATFORM_THEME_LOCK).then((info) => Date.now() - info.mtimeMs, () => 0);
    if (age > PLATFORM_THEME_LOCK_STALE_MS) {
      await rm(PLATFORM_THEME_LOCK, { recursive: true, force: true });
    } else {
      await new Promise((resolve) => {
        setTimeout(resolve, PLATFORM_THEME_LOCK_RETRY_MS);
      });
    }
    await takePlatformThemeLock(owner);
  }
};

/**
 * Waits until no other test file holds the platform theme, takes it, and returns the function
 * that gives it back. The platform theme colours every page of every test: a file that changes
 * it, or that compares screenshots, holds it so that local runs, which execute several files at
 * once, never overlap them. The lock is a directory, created atomically by one worker only; its
 * holder renews the lease while it holds it, so only a lock left by a killed run expires, and the
 * lock is removed by its owner only.
 */
export const acquirePlatformThemeLock = async (): Promise<() => Promise<void>> => {
  const owner = `${process.pid}-${randomUUID()}`;
  await takePlatformThemeLock(owner);
  const heartbeat = setInterval(() => {
    const now = new Date();
    utimes(PLATFORM_THEME_LOCK, now, now).catch(() => undefined);
  }, PLATFORM_THEME_LOCK_HEARTBEAT_MS);
  return async () => {
    clearInterval(heartbeat);
    const holder = await readFile(PLATFORM_THEME_LOCK_OWNER, 'utf8').catch(() => null);
    if (holder === owner) await rm(PLATFORM_THEME_LOCK, { recursive: true, force: true });
  };
};
