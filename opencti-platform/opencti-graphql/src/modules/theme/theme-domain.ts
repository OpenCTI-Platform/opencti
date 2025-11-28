import type { FileHandle } from 'fs/promises';
import { z } from 'zod';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { updateAttribute } from '../../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { type EditInput, FilterMode, FilterOperator, type QueryThemesArgs, type ThemeAddInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_THEME } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityTheme, type StoreEntityTheme } from './theme-types';
import { FunctionalError } from '../../config/errors';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { extractContentFrom } from '../../utils/fileToContent';
import { SYSTEM_USER } from '../../utils/access';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from './theme-constants';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityTheme>(context, user, id, ENTITY_TYPE_THEME);
};

export const findThemePaginated = async (context: AuthContext, user: AuthUser, args: QueryThemesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityTheme>(context, user, [ENTITY_TYPE_THEME], args);
};

const checkExistingTheme = async (context: AuthContext, user: AuthUser, themeName: string) => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: [themeName], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, user, { filters });
  return themes.edges.findIndex((edge) => edge.node.name === themeName) > -1;
};

export const addTheme = async (context: AuthContext, user: AuthUser, input: ThemeAddInput) => {
  const themeFound = await checkExistingTheme(context, user, input.name);

  if (themeFound) {
    throw FunctionalError('Theme name already exists');
  }

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
    built_in: input.built_in ?? false,
  };

  return createInternalObject<StoreEntityTheme>(context, user, themeToCreate, ENTITY_TYPE_THEME);
};

export const initDefaultTheme = async (context: AuthContext, user = SYSTEM_USER) => {
  logApp.info('[INIT] Theme defaults starts initialization');

  // Create Dark theme with user customizations or defaults
  const darkThemeInput = {
    name: 'Dark',
    theme_background: DARK_DEFAULTS.theme_background,
    theme_paper: DARK_DEFAULTS.theme_paper,
    theme_nav: DARK_DEFAULTS.theme_nav,
    theme_primary: DARK_DEFAULTS.theme_primary,
    theme_secondary: DARK_DEFAULTS.theme_secondary,
    theme_accent: DARK_DEFAULTS.theme_accent,
    theme_text_color: DARK_DEFAULTS.theme_text_color,
    theme_logo: DARK_DEFAULTS.theme_logo,
    theme_logo_collapsed: DARK_DEFAULTS.theme_logo_collapsed,
    theme_logo_login: DARK_DEFAULTS.theme_logo_login,
    built_in: true,
  };

  const darkTheme = await addTheme(context, user, darkThemeInput);

  const lightThemeInput = {
    name: 'Light',
    theme_background: LIGHT_DEFAULTS.theme_background,
    theme_paper: LIGHT_DEFAULTS.theme_paper,
    theme_nav: LIGHT_DEFAULTS.theme_nav,
    theme_primary: LIGHT_DEFAULTS.theme_primary,
    theme_secondary: LIGHT_DEFAULTS.theme_secondary,
    theme_accent: LIGHT_DEFAULTS.theme_accent,
    theme_text_color: LIGHT_DEFAULTS.theme_text_color,
    theme_logo: LIGHT_DEFAULTS.theme_logo,
    theme_logo_collapsed: LIGHT_DEFAULTS.theme_logo_collapsed,
    theme_logo_login: LIGHT_DEFAULTS.theme_logo_login,
    built_in: true,
  };

  await addTheme(context, user, lightThemeInput);

  logApp.info('[INIT] Theme defaults initialized');
  return darkTheme;
};

export const deleteTheme = async (context: AuthContext, user: AuthUser, themeId: string) => {
  const theme = await findById(context, user, themeId);
  if (!theme) {
    throw FunctionalError(`Theme ${themeId} cannot be found`);
  }
  if (theme.built_in) {
    throw FunctionalError('System default themes cannot be deleted');
  }
  return deleteInternalObject(context, user, themeId, ENTITY_TYPE_THEME);
};

export const fieldPatchTheme = async (context: AuthContext, user: AuthUser, themeId: string, input: EditInput[]) => {
  const theme = await findById(context, user, themeId);
  if (!theme) {
    throw FunctionalError(`Theme ${themeId} cannot be found`);
  }
  const { element } = await updateAttribute<StoreEntityTheme>(context, user, themeId, ENTITY_TYPE_THEME, input);
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

const themeImportSchema = z.object({
  name: z.string().min(1, 'Theme name is required'),
  theme_background: z.string().min(1, 'Background color is required'),
  theme_paper: z.string().min(1, 'Paper color is required'),
  theme_nav: z.string().min(1, 'Nav color is required'),
  theme_primary: z.string().min(1, 'Primary color is required'),
  theme_secondary: z.string().min(1, 'Secondary color is required'),
  theme_accent: z.string().min(1, 'Accent color is required'),
  theme_text_color: z.string().min(1, 'Text color is required'),
  theme_logo: z.string().optional().default(''),
  theme_logo_collapsed: z.string().optional().default(''),
  theme_logo_login: z.string().optional().default(''),
});

export const themeImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);

  const validationResult = themeImportSchema.safeParse(parsedData);

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ');
    throw FunctionalError('Invalid theme file', errors);
  }

  const themeFound = await checkExistingTheme(context, user, validationResult.data.name);

  if (themeFound) {
    throw FunctionalError('Theme name already exists');
  }

  return addTheme(context, user, validationResult.data);
};
