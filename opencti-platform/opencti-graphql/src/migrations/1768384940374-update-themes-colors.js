import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { findThemePaginated, fieldPatchTheme } from '../modules/theme/theme-domain';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';

const message = '[MIGRATION] update themes colors';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: ['Light', 'Dark'], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const context = executionContext('migration');
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  const formattedThemes = themes.edges.map((edge) => {
    if (edge.node.name === 'Dark') {
      return {
        id: edge.node.id,
        name: edge.node.name,
        theme_secondary: edge.node.theme_secondary === '#00f1bd'
          ? DARK_DEFAULTS.theme_secondary
          : edge.node.theme_secondary,
        theme_text_color: edge.node.theme_text_color === '#ffffff'
          ? DARK_DEFAULTS.theme_text_color
          : edge.node.theme_text_color,
      };
    } else if (edge.node.name === 'Light') {
      return {
        id: edge.node.id,
        name: edge.node.name,
        theme_primary: edge.node.theme_primary === '#001bda'
          ? LIGHT_DEFAULTS.theme_primary
          : edge.node.theme_primary,
        theme_secondary: edge.node.theme_secondary === '#0c7e69'
          ? LIGHT_DEFAULTS.theme_secondary
          : edge.node.theme_secondary,
        theme_text_color: edge.node.theme_text_color === '#000000'
          ? LIGHT_DEFAULTS.theme_text_color
          : edge.node.theme_text_color,
      };
    }
  });

  const darkTheme = formattedThemes.find((theme) => theme.name === 'Dark');
  const inputDark = [
    { key: 'theme_secondary', value: [darkTheme.theme_secondary] },
    { key: 'theme_text_color', value: [darkTheme.theme_text_color] },
  ];

  const lightTheme = formattedThemes.find((theme) => theme.name === 'Light');
  const inputLight = [
    { key: 'theme_primary', value: [lightTheme.theme_primary] },
    { key: 'theme_secondary', value: [lightTheme.theme_secondary] },
    { key: 'theme_text_color', value: [lightTheme.theme_text_color] },
  ];

  if (darkTheme) {
    await fieldPatchTheme(context, SYSTEM_USER, darkTheme.id, inputDark);
  }
  if (lightTheme) {
    await fieldPatchTheme(context, SYSTEM_USER, lightTheme.id, inputLight);
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
