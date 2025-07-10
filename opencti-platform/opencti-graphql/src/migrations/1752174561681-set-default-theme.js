import { logMigration } from '../config/conf';
import { getEntityFromCache } from '../database/cache';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { findAll } from '../modules/theme/theme-domain';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Replacing platform theme with Theme ID';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const { platform_theme } = await getEntityFromCache(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_SETTINGS,
  );
  const themes = await findAll(context, {});

  let themeId;
  switch (platform_theme) {
    case 'dark':
    case 'Dark':
      themeId = themes.edges.find(({ node }) => node?.name === 'Dark')?.node.id;
      break;
    case 'light':
    case 'Light':
      themeId = themes.edges.find(({ node }) => node?.name === 'Light')?.node.id;
      break;
    default:
      break;
  }

  if (themeId) {
    logMigration.info(`${message} > changing platform theme from ${platform_theme} to ${themeId}`);
    const updateQuery = {
      query: {
        match: {
          'entity_type.keyword': 'Settings'
        }
      },
      script: {
        source: `ctx._source.platform_theme = '${themeId}'`,
        lang: 'painless'
      }
    };
    await elUpdateByQueryForMigration(
      message,
      [READ_INDEX_INTERNAL_OBJECTS],
      updateQuery,
    );
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
