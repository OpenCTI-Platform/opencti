import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { ENTITY_SETTING_PROVENANCE_RELATIONSHIP_TYPES, PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES_SETTING } from '../modules/provenance/provenance-tracking';

const message = '[MIGRATION] Track the provenance of the recommended relationship types';

/**
 * Provenance tracking is now configured per relationship type. The recommended types (uses, targets, attributed-to)
 * are tracked out of the box, as on a new platform; every other relationship type keeps its current tracking.
 * Each type can still be turned off in "Settings > Customization > Entity types > Relationships".
 */
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: `ctx._source.${ENTITY_SETTING_PROVENANCE_RELATIONSHIP_TYPES} = params.types;`,
      lang: 'painless',
      params: { types: PROVENANCE_RECOMMENDED_RELATIONSHIP_TYPES_SETTING },
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': ENTITY_TYPE_ENTITY_SETTING } },
          { term: { 'target_type.keyword': ABSTRACT_STIX_CORE_RELATIONSHIP } },
        ],
        must_not: [{ exists: { field: ENTITY_SETTING_PROVENANCE_RELATIONSHIP_TYPES } }],
      },
    },
  };
  await elUpdateByQueryForMigration(message, READ_INDEX_INTERNAL_OBJECTS, updateQuery);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
