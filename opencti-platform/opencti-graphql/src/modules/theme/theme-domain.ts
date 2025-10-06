import { BUS_TOPICS } from '../../config/conf';
import { updateAttribute } from '../../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { EditInput, QueryThemesArgs, ThemeAddInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_THEME } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityTheme, type StoreEntityTheme } from './theme-types';
import { FunctionalError } from '../../config/errors';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { SYSTEM_USER } from '../../utils/access';

// const defaultLightTheme: ThemeAddInput = {
//   name: 'Light',
//   manifest: 'eyJ0aGVtZV9iYWNrZ3JvdW5kIjoiI2Y4ZjhmOCIsInRoZW1lX3BhcGVyIjoiI2ZmZmZmZiIsInRoZW1lX25hdiI6IiNmZmZmZmYiLCJ0aGVtZV9wcmltYXJ5IjoiIzAwMWJkYSIsInRoZW1lX3NlY29uZGFyeSI6IiMwYzdlNjkiLCJ0aGVtZV9hY2NlbnQiOiIjZWVlZWVlIiwidGhlbWVfdGV4dF9jb2xvciI6IiMwMDAwMDAiLCJ0aGVtZV9sb2dvIjoiIiwidGhlbWVfbG9nb19jb2xsYXBzZWQiOiIiLCJ0aGVtZV9sb2dvX2xvZ2luIjoiIiwic3lzdGVtX2RlZmF1bHQiOnRydWV9',
// };
//
// const defaultDarkTheme: ThemeAddInput = {
//   name: 'Dark',
//   manifest: 'eyJ0aGVtZV9iYWNrZ3JvdW5kIjoiIzA3MGQxOSIsInRoZW1lX3BhcGVyIjoiIzA5MTAxZSIsInRoZW1lX25hdiI6IiMwNzBkMTkiLCJ0aGVtZV9wcmltYXJ5IjoiIzBmYmNmZiIsInRoZW1lX3NlY29uZGFyeSI6IiMwMGYxYmQiLCJ0aGVtZV9hY2NlbnQiOiIjMGYxZTM4IiwidGhlbWVfdGV4dF9jb2xvciI6IiNmZmZmZmYiLCJ0aGVtZV9sb2dvIjoiIiwidGhlbWVfbG9nb19jb2xsYXBzZWQiOiIiLCJ0aGVtZV9sb2dvX2xvZ2luIjoiIiwic3lzdGVtX2RlZmF1bHQiOnRydWV9',
// };

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  // FIXME: use SYSTEM_USER instead of user because on public page such as
  // Login, the components is using the theme to get logo
  return storeLoadById<BasicStoreEntityTheme>(context, SYSTEM_USER, id, ENTITY_TYPE_THEME,);
};

export const findThemePaginated = async (context: AuthContext, user: AuthUser, args: QueryThemesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityTheme>(context, SYSTEM_USER, [ENTITY_TYPE_THEME], args);
};

export const addTheme = async (context: AuthContext, user: AuthUser, input: ThemeAddInput) => {
  const themeToCreate = {
    name: input.name,
    theme_background: input.theme_background,
    theme_paper: input.theme_paper,
    theme_nav: input.theme_nav,
    theme_primary: input.theme_primary,
    theme_secondary: input.theme_secondary,
    theme_accent: input.theme_accent,
    theme_logo: input.theme_logo,
    theme_logo_collapsed: input.theme_logo_collapsed,
    theme_logo_login: input.theme_logo_login,
    theme_text_color: input.theme_text_color,
    system_default: input.system_default ?? false,
  };
  const created = await createInternalObject<StoreEntityTheme>(context, user, themeToCreate, ENTITY_TYPE_THEME);

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

export const deleteTheme = async (context: AuthContext, user: AuthUser, themeId: string) => {
  const theme = await findById(context, user, themeId);
  if (!theme) {
    throw FunctionalError(`Theme ${themeId} cannot be found`);
  }
  if (theme.system_default === true) {
    throw FunctionalError('System default themes cannot be deleted');
  }
  return deleteInternalObject(context, user, themeId, ENTITY_TYPE_THEME);
};

export const fieldPatchTheme = async (context: AuthContext, user: AuthUser, themeId: string, input: EditInput[]) => {
  const theme = await findById(context, user, themeId);
  if (!theme) {
    throw FunctionalError(`Theme ${themeId} cannot be found`);
  }
  const { element } = await updateAttribute(context, user, themeId, ENTITY_TYPE_THEME, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for theme \`${element.name}\``,
    context_data: { id: element.id, entity_type: ENTITY_TYPE_THEME, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_THEME].EDIT_TOPIC, element, user);
};

// const checkExistingTheme = async (
//   context: AuthContext,
//   name: string,
//   edit_id?: string,
// ) => {
//   const existingTheme = await elLoadBy(
//     context,
//     SYSTEM_USER,
//     'name',
//     name,
//     // eslint-disable-next-line @typescript-eslint/ban-ts-comment
//     // @ts-expect-error elLoadBy in engine.js implicitly defines type as null
//     ENTITY_TYPE_THEME
//   );
//   if (existingTheme) {
//     // eslint-disable-next-line @typescript-eslint/ban-ts-comment
//     // @ts-expect-error TypeScript erroneously infers type as string
//     if (edit_id !== existingTheme.internal_id) {
//       throw FunctionalError(
//         'Theme already exists',
//         // eslint-disable-next-line @typescript-eslint/ban-ts-comment
//         // @ts-expect-error TypeScript erroneously infers type as string
//         { theme_id: existingTheme.internal_id }
//       );
//     }
//   }
// };
//
// export const addTheme = async (
//   context: AuthContext,
//   user: AuthUser,
//   input: ThemeAddInput,
// ) => {
//   await checkExistingTheme(context, input.name);
//   const created = await createEntity(context, user, input, ENTITY_TYPE_THEME);
//
//   await publishUserAction({
//     user,
//     event_type: 'mutation',
//     event_scope: 'create',
//     event_access: 'extended',
//     message: `creates theme \`${created.name}\``,
//     context_data: {
//       id: created.id,
//       entity_type: ENTITY_TYPE_THEME,
//       input,
//     },
//   });
//
//   return notify(BUS_TOPICS[ENTITY_TYPE_THEME].ADDED_TOPIC, created, user);
// };

// export const findAll = async (
//   context: AuthContext,
//   opts: EntityOptions<BasicStoreEntityTheme>,
// ) => pageEntitiesConnection<BasicStoreEntityTheme>(
//   context,
//   SYSTEM_USER,
//   [ENTITY_TYPE_THEME],
//   opts,
// ).then(async (storeEntityConnection) => {
//   if (storeEntityConnection.edges.length > 0) return storeEntityConnection;
//
//   // If there are no themes present when searching globally, add the default light and dark themes.
//   if (Object.keys(opts).length < 1) {
//     await addTheme(context, SYSTEM_USER, defaultLightTheme);
//     await addTheme(context, SYSTEM_USER, defaultDarkTheme);
//   }
//
//   return pageEntitiesConnection<BasicStoreEntityTheme>(
//     context,
//     SYSTEM_USER,
//     [ENTITY_TYPE_THEME],
//     opts,
//   );
// });

// export const deleteTheme = async (
//   context: AuthContext,
//   user: AuthUser,
//   id: string,
// ) => {
//   const deleted = await deleteElementById(
//     context,
//     user,
//     id,
//     ENTITY_TYPE_THEME,
//   );

// await publishUserAction({
//   user,
//   event_type: 'mutation',
//   event_scope: 'delete',
//   event_access: 'extended',
//   message: `deletes theme \`${deleted.name}\``,
//   context_data: {
//     id: deleted.id,
//     entity_type: ENTITY_TYPE_THEME,
//     input: deleted,
//   },
// });

//   return notify(BUS_TOPICS[ENTITY_TYPE_THEME].DELETE_TOPIC, deleted, user).then(() => id);
// };

// export const editTheme = async (
//   context: AuthContext,
//   user: AuthUser,
//   id: string,
//   input: EditInput[],
// ) => {
//   // Check if new name conflicts with an existing theme's name
//   const updatedName = input.find(({ key }) => key === 'name')?.value?.[0];
//   if (updatedName && typeof updatedName === 'string') {
//     await checkExistingTheme(context, updatedName, id);
//   }
//
//   const { element } = await updateAttribute(
//     context,
//     user,
//     id,
//     ENTITY_TYPE_THEME,
//     input,
//   );
//
//   await publishUserAction({
//     user,
//     event_type: 'mutation',
//     event_scope: 'update',
//     event_access: 'administration',
//     message: `update theme with id:\`${element.id}\``,
//     context_data: {
//       id: element.id,
//       entity_type: ENTITY_TYPE_THEME,
//       input,
//     },
//   });
//
//   return notify(BUS_TOPICS[ENTITY_TYPE_THEME].EDIT_TOPIC, element, user);
// };

// const convertThemeManifestIds = (manifest: string) => {
//   const parsedManifest = JSON.parse(fromBase64(manifest) ?? '{}');
//
//   // Disable system default flag on export, so importing these themes don't
//   // produce undeletable themes.
//   try {
//     if (parsedManifest?.system_default) {
//       parsedManifest.system_default = false;
//     }
//   } catch {
//     logApp.error('[THEME] Failed to disable system default flag in exported theme');
//   }
//
//   if (parsedManifest && isNotEmptyField(parsedManifest)) {
//     return toBase64(JSON.stringify(parsedManifest)) as string;
//   }
//   return manifest;
// };
//
// export const generateThemeExportConfiguration = async (
//   theme: BasicStoreEntityTheme,
// ) => {
//   const generatedManifest = convertThemeManifestIds(theme.manifest);
//   const exportConfiguration = {
//     openCTI_version: pjson.version,
//     type: 'theme',
//     configuration: {
//       name: theme.name,
//       manifest: generatedManifest,
//     },
//   };
//   return JSON.stringify(exportConfiguration);
// };
//
// export const themeImport = async (
//   context: AuthContext,
//   user: AuthUser,
//   file: Promise<FileHandle>,
// ) => {
//   const parsedData = await extractContentFrom(file);
//   checkConfigurationImport('theme', parsedData);
//   const mappedData = {
//     openCTI_version: parsedData.openCTI_version,
//     type: parsedData.type,
//     name: parsedData.configuration.name,
//     manifest: parsedData.configuration.manifest,
//   };
//   await checkExistingTheme(context, mappedData.name);
//   const importThemeCreation = await createEntity(context, user, mappedData, ENTITY_TYPE_THEME);
//   const themeId = importThemeCreation.id;
//   await publishUserAction({
//     user,
//     event_type: 'mutation',
//     event_scope: 'create',
//     event_access: 'extended',
//     message: `import ${importThemeCreation.name} theme`,
//     context_data: {
//       id: themeId,
//       entity_type: ENTITY_TYPE_THEME,
//       input: importThemeCreation,
//     },
//   });
//   await notify(BUS_TOPICS[ENTITY_TYPE_THEME].ADDED_TOPIC, importThemeCreation, user);
//   return importThemeCreation;
// };
