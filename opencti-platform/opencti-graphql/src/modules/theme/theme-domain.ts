import { toBase64 } from 'openai/core';
import type { FileHandle } from 'fs/promises';
import { BUS_TOPICS } from '../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { listEntitiesPaginated, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { fromBase64, isNotEmptyField } from '../../database/utils';
import type { EditInput, ThemeAddInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_THEME } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type BasicStoreEntityTheme } from './theme-types';
import pjson from '../../../package.json';
import { extractContentFrom } from '../../utils/fileToContent';
import { checkConfigurationImport } from '../workspace/workspace-domain';

const defaultLightTheme: ThemeAddInput = {
  name: 'Light',
  manifest: 'eyJ0aGVtZV9iYWNrZ3JvdW5kIjoiI2Y4ZjhmOCIsInRoZW1lX3BhcGVyIjoiI2ZmZmZmZiIsInRoZW1lX25hdiI6IiNmZmZmZmYiLCJ0aGVtZV9wcmltYXJ5IjoiIzAwMWJkYSIsInRoZW1lX3NlY29uZGFyeSI6IiMwYzdlNjkiLCJ0aGVtZV9hY2NlbnQiOiIjZWVlZWVlIiwidGhlbWVfbG9nbyI6IiIsInRoZW1lX2xvZ29fY29sbGFwc2VkIjoiIiwidGhlbWVfbG9nb19sb2dpbiI6IiIsInN5c3RlbV9kZWZhdWx0Ijp0cnVlfQ==',
};

const defaultDarkTheme: ThemeAddInput = {
  name: 'Dark',
  manifest: 'eyJ0aGVtZV9iYWNrZ3JvdW5kIjoiIzA3MGQxOSIsInRoZW1lX3BhcGVyIjoiIzA5MTAxZSIsInRoZW1lX25hdiI6IiMwNzBkMTkiLCJ0aGVtZV9wcmltYXJ5IjoiIzBmYmNmZiIsInRoZW1lX3NlY29uZGFyeSI6IiMwMGYxYmQiLCJ0aGVtZV9hY2NlbnQiOiIjMGYxZTM4IiwidGhlbWVfbG9nbyI6IiIsInRoZW1lX2xvZ29fY29sbGFwc2VkIjoiIiwidGhlbWVfbG9nb19sb2dpbiI6IiIsInN5c3RlbV9kZWZhdWx0Ijp0cnVlfQ==',
};

export const findById = (
  context: AuthContext,
  id: string,
) => storeLoadById<BasicStoreEntityTheme>(
  context,
  SYSTEM_USER,
  id,
  ENTITY_TYPE_THEME,
);

export const addTheme = async (
  context: AuthContext,
  user: AuthUser,
  input: ThemeAddInput,
) => {
  const created = await createEntity(context, user, input, ENTITY_TYPE_THEME);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates theme \`${created.name}\``,
    context_data: {
      id: created.id,
      entity_type: ENTITY_TYPE_THEME,
      input,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_THEME].ADDED_TOPIC, created, user);
};

export const findAll = async (
  context: AuthContext,
  opts: EntityOptions<BasicStoreEntityTheme>,
) => listEntitiesPaginated<BasicStoreEntityTheme>(
  context,
  SYSTEM_USER,
  [ENTITY_TYPE_THEME],
  opts,
).then(async (storeEntityConnection) => {
  if (storeEntityConnection.edges.length > 0) return storeEntityConnection;

  // If there are no themes present, add the default light and dark themes.
  await addTheme(context, SYSTEM_USER, defaultLightTheme);
  await addTheme(context, SYSTEM_USER, defaultDarkTheme);

  return listEntitiesPaginated<BasicStoreEntityTheme>(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_THEME],
    opts,
  );
});

export const deleteTheme = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
) => {
  const deleted = await deleteElementById(
    context,
    user,
    id,
    ENTITY_TYPE_THEME,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes theme \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_THEME,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_THEME].DELETE_TOPIC, deleted, user).then(() => id);
};

export const editTheme = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: EditInput[],
) => {
  const { element } = await updateAttribute(
    context,
    user,
    id,
    ENTITY_TYPE_THEME,
    input,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `update theme with id:\`${element.id}\``,
    context_data: {
      id: element.id,
      entity_type: ENTITY_TYPE_THEME,
      input,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_THEME].EDIT_TOPIC, element, user);
};

const convertThemeManifestIds = (manifest: string) => {
  const parsedManifest = JSON.parse(fromBase64(manifest) ?? '{}');
  if (parsedManifest && isNotEmptyField(parsedManifest)) {
    return toBase64(JSON.stringify(parsedManifest)) as string;
  }
  return manifest;
};

export const generateThemeExportConfiguration = async (
  theme: BasicStoreEntityTheme,
) => {
  const generatedManifest = convertThemeManifestIds(theme.manifest);
  const exportConfiguration = {
    openCTI_version: pjson.version,
    type: 'theme',
    configuration: {
      name: theme.name,
      manifest: generatedManifest,
    },
  };
  return JSON.stringify(exportConfiguration);
};

export const themeImport = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileHandle>,
) => {
  const parsedData = await extractContentFrom(file);
  checkConfigurationImport('theme', parsedData);
  const mappedData = {
    openCTI_version: parsedData.openCTI_version,
    type: parsedData.type,
    name: parsedData.configuration.name,
    manifest: parsedData.configuration.manifest,
  };
  const importThemeCreation = await createEntity(context, user, mappedData, ENTITY_TYPE_THEME);
  const themeId = importThemeCreation.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importThemeCreation.name} theme`,
    context_data: {
      id: themeId,
      entity_type: ENTITY_TYPE_THEME,
      input: importThemeCreation,
    },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_THEME].ADDED_TOPIC, importThemeCreation, user);
  return importThemeCreation;
};
