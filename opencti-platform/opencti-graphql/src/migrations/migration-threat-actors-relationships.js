import { logApp } from '../config/conf';
import { elReindexByQueryForMigration, elUpdateByQueryForMigration, elDeleteByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { executionContext } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Transform invalid relationships to "related-to"');

  // Définition des relations valides avec direction
  const validRelations = [
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'part-of' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'employed-by' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'cooperates-with' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'derived-from' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'related-to' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Individual', relationType: 'known-as' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Individual', relationType: 'reports-to' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Individual', relationType: 'supports' },
    { fromType: 'Threat-Actor-Individual', toType: 'Threat-Actor-Group', relationType: 'supports' },
    { fromType: 'Threat-Actor-Group', toType: 'Threat-Actor-Individual', relationType: 'cooperates-with' },
    { fromType: 'Threat-Actor-Group', toType: 'Threat-Actor-Individual', relationType: 'derived-from' },
    { fromType: 'Threat-Actor-Group', toType: 'Threat-Actor-Individual', relationType: 'related-to' },
  ];

  // Étape 1 : Identifier les relations invalides
  const invalidRelationshipsQuery = {
    bool: {
      must_not: validRelations.map((relation) => ({
        bool: {
          must: [
            { term: { 'fromType.keyword': relation.fromType } },
            { term: { 'toType.keyword': relation.toType } },
            { term: { 'relationship_type.keyword': relation.relationType } },
          ],
        },
      })),
    },
  };

  // Étape 2 : Reindexer les relations invalides
  const reindexInvalidRelationshipsSource = `
    ctx._source.relationship_type = params.newRelType;
    ctx._source.entity_type = params.newRelType;
    ctx._source.parent_types = params.parentTypes;
    for (connection in ctx._source.connections) {
      connection.role = connection.role.replace(connection.role, "related-to_" + connection.role.split("_")[1]);
    }
  `;
  const reindexInvalidRelationshipsQuery = {
    source: {
      index: READ_INDEX_STIX_CORE_RELATIONSHIPS,
      query: invalidRelationshipsQuery,
    },
    dest: {
      index: READ_INDEX_STIX_CORE_RELATIONSHIPS,
    },
    script: {
      source: reindexInvalidRelationshipsSource,
      params: {
        newRelType: RELATION_RELATED_TO,
        parentTypes: ['basic-relationship', 'stix-relationship', 'stix-core-relationship'],
      },
    },
  };

  logApp.info('[MIGRATION] Reindexing invalid relationships to "related-to"');
  await elReindexByQueryForMigration(
    '[MIGRATION] Reindexing invalid relationships',
    null,
    reindexInvalidRelationshipsQuery
  );

  // Étape 3 : Mise à jour des connexions dans les entités
  const updateInvalidConnectionsSource = `
    if (!params.validRelations.some(
        r => r.fromType == ctx._source.fromType && r.toType == ctx._source.toType && r.relationType == ctx._source.relationship_type)) {
      ctx._source.relationship_type = params.newRelType;
      ctx._source.entity_type = params.newRelType;
      for (connection in ctx._source.connections) {
        connection.role = connection.role.replace(connection.role, "related-to_" + connection.role.split("_")[1]);
      }
    }
  `;
  const updateInvalidConnectionsQuery = {
    script: {
      source: updateInvalidConnectionsSource,
      params: { validRelations, newRelType: RELATION_RELATED_TO },
    },
    query: invalidRelationshipsQuery,
  };

  logApp.info('[MIGRATION] Updating invalid relationships in entities');
  await elUpdateByQueryForMigration(
    '[MIGRATION] Updating invalid relationships in entities',
    [READ_RELATIONSHIPS_INDICES],
    updateInvalidConnectionsQuery
  );

  // Étape 4 : Suppression des relations invalides d'origine
  logApp.info('[MIGRATION] Deleting old invalid relationships');
  await elDeleteByQueryForMigration(
    '[MIGRATION] Deleting invalid relationships',
    [READ_INDEX_STIX_CORE_RELATIONSHIPS],
    {
      query: invalidRelationshipsQuery,
    }
  );

  logApp.info('[MIGRATION] Transform invalid relationships to "related-to" completed');
  next();
};

export const down = async (next) => {
  next();
};
