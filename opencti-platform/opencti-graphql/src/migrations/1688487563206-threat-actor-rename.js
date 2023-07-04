import { elUpdateByQueryForMigration } from '../database/engine';
import {
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED
} from '../database/utils';
import { DatabaseError } from '../config/errors';

const entityTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'ctx._source.entity_type = params.toType;'
    },
    query: {
      term: { 'entity_type.keyword': { value: fromType } }
    },
  };
  const message = `[MIGRATION] Rewriting entity type from ${fromType} to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const targetTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'ctx._source.target_type = params.toType;'
    },
    query: {
      term: { 'target_type.keyword': { value: fromType } }
    },
  };
  const message = `[MIGRATION] Rewriting target type from ${fromType} to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const relationshipFromTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'for(def connection : ctx._source.connections) {'
        + 'if (connection.types.contains("Threat-Actor")) { '
        + 'connection.types = params.toType; '
        + '} } '
        + 'ctx._source.fromType = params.toType'
    },
    query: {
      term: { 'fromType.keyword': { value: fromType } }
    },
  };
  const message = `[MIGRATION] Rewriting relationship fromType types from ${fromType} to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const relationshipToTypeChange = (fromType, toType, indices) => {
  const updateQuery = {
    script: {
      params: { toType },
      source: 'for(def connection : ctx._source.connections) {'
        + 'if (connection.types.contains("Threat-Actor")) { '
        + 'connection.types = params.toType; '
        + '} } '
        + 'ctx._source.toType = params.toType'
    },
    query: {
      term: { 'toType.keyword': { value: fromType } }
    },
  };
  const message = `[MIGRATION] Rewriting relationship toType types from ${fromType} to ${toType}`;
  return elUpdateByQueryForMigration(message, indices, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

export const up = async (next) => {
  // Change Threat Actor type to Threat Actor Group
  await entityTypeChange('Threat-Actor', 'Threat-Actor-Group', READ_INDEX_STIX_DOMAIN_OBJECTS);
  await targetTypeChange('Threat-Actor', 'Threat-Actor-Group', [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_RELATIONSHIPS]);
  await relationshipFromTypeChange('Threat-Actor', 'Threat-Actor-Group', READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED);
  await relationshipToTypeChange('Threat-Actor', 'Threat-Actor-Group', READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED);
  next();
};

export const down = async (next) => {
  next();
};
