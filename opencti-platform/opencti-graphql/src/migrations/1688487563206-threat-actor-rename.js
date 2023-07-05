import { elUpdateByQueryForMigration } from '../database/engine';
import {
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED
} from '../database/utils';
import { DatabaseError } from '../config/errors';

const entityTypeChange = (toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType, initial: 'Threat-Actor' },
      source: 'ctx._source.entity_type = params.toType; ctx._source.parent_types.add(params.initial);'
    },
    query: {
      term: { 'entity_type.keyword': { value: 'Threat-Actor' } }
    },
  };
  const message = `[MIGRATION] Rewriting entity type from Threat-Actor to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const targetTypeChange = (toType, indices) => {
  // TODO JRI standard_id must be regenerated, need to change this method
  const updateQuery = {
    script: {
      params: { toType },
      source: 'ctx._source.target_type = params.toType;'
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'EntitySetting' } } },
          { term: { 'target_type.keyword': { value: 'Threat-Actor' } } }
        ],
      },
    },
  };
  const message = `[MIGRATION] Rewriting target type from Threat-Actor to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const relationshipFromTypeChange = (toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'for(def connection : ctx._source.connections) {'
        + 'if (connection.types.contains("Threat-Actor")) { '
        + 'connection.types.add(params.toType);'
        + '} } '
        + 'if (ctx._source.fromType == "Threat-Actor") { ctx._source.fromType = params.toType; }'
        + 'if (ctx._source.toType == "Threat-Actor") { ctx._source.toType = params.toType; }'
    },
    query: {
      bool: {
        should: [
          { term: { 'fromType.keyword': { value: 'Threat-Actor' } } },
          { term: { 'toType.keyword': { value: 'Threat-Actor' } } }
        ],
      }
    },
  };
  const message = `[MIGRATION] Rewriting relationship fromType types from Threat-Actor to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

export const up = async (next) => {
  // Entity settings
  await targetTypeChange('Threat-Actor-Group', [READ_INDEX_INTERNAL_OBJECTS]);
  // Change Threat Actor type to Threat Actor Group
  const promiseEntities = entityTypeChange('Threat-Actor-Group', READ_INDEX_STIX_DOMAIN_OBJECTS);
  // Relationships
  const promiseRelations = relationshipFromTypeChange('Threat-Actor-Group', READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED);
  // Execute both in parallel as they used different indices
  await Promise.all([promiseEntities, promiseRelations]);
  next();
};

export const down = async (next) => {
  next();
};
