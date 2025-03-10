import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration, elList, elRawCount } from '../database/engine';
import { READ_DATA_INDICES, READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { RELATION_DERIVED_FROM, RELATION_PART_OF, RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Transform invalid threat-actors relationships to "related-to"');

  const relRelatedTo = `rel_${RELATION_RELATED_TO}.internal_id`;
  const taiTargetTaiFilter = {
    filterGroups: [],
    filters: [
      {
        key: 'fromTypes',
        mode: 'or',
        operator: 'eq',
        values: [
          'Threat-Actor-Individual'
        ]
      },
      {
        key: 'toTypes',
        mode: 'or',
        operator: 'eq',
        values: [
          'Threat-Actor-Individual'
        ]
      }
    ],
    mode: 'and'
  };
  const tagTargetTaiFilter = {
    filterGroups: [],
    filters: [
      {
        key: 'fromTypes',
        mode: 'or',
        operator: 'eq',
        values: [
          'Threat-Actor-Group'
        ]
      },
      {
        key: 'toTypes',
        mode: 'or',
        operator: 'eq',
        values: [
          'Threat-Actor-Individual'
        ]
      }
    ],
    mode: 'and'
  };
  // We get all current part-of & derived-from relations: will be used to check for duplicates in part-of/derived-from to related-to migration
  const getTAIPartOfRelation = await elList(context, SYSTEM_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, {
    types: [RELATION_PART_OF],
    filters: taiTargetTaiFilter
  });
  const getTAGPartOfRelation = await elList(context, SYSTEM_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, {
    types: [RELATION_PART_OF],
    filters: tagTargetTaiFilter
  });
  const getTAIDerivedFromRelation = await elList(context, SYSTEM_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, {
    types: [RELATION_DERIVED_FROM],
    filters: taiTargetTaiFilter
  });

  const invalidRelationships = [...getTAIDerivedFromRelation, ...getTAIPartOfRelation, ...getTAGPartOfRelation];
  // If no invalidRelationships exist, we can skip the migration process
  if (invalidRelationships.length === 0) {
    logApp.info('[MIGRATION] Update all invalid relationships between threat-actors: no relationships to migrate');
    next();
    return;
  }
  logApp.info(`[MIGRATION] Update all invalid threat-actors relationships to related-to: ${invalidRelationships.length} relationships to migrate`);

  const searchRelatedToDuplicateFn = async (from, to) => {
    const countDuplicateQueryBody = {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: RELATION_RELATED_TO } } },
          {
            nested: {
              path: 'connections',
              query: {
                bool: {
                  must: [
                    { term: { 'connections.role.keyword': { value: 'related-to_from' } } },
                    { term: { 'connections.internal_id.keyword': { value: from } } }
                  ]
                }
              }
            }
          },
          {
            nested: {
              path: 'connections',
              query: {
                bool: {
                  must: [
                    { term: { 'connections.role.keyword': { value: 'related-to_to' } } },
                    { term: { 'connections.internal_id.keyword': { value: to } } }
                  ]
                }
              }
            }
          }
        ]
      }
    };
    const findQuery = {
      index: READ_INDEX_STIX_CORE_RELATIONSHIPS,
      body: { query: countDuplicateQueryBody },
    };

    const rawCount = await elRawCount(findQuery);
    return rawCount > 0;
  };

  const invalidRelationsDuplicatesIds = [];
  for (let i = 0; i < invalidRelationships.length; i+=1) {
    const invalidRelationship = invalidRelationships[i];
    const hasDuplicate = await searchRelatedToDuplicateFn(invalidRelationship.fromId, invalidRelationship.toId);
    if (hasDuplicate) invalidRelationsDuplicatesIds.push(invalidRelationship.internal_id);
  }

  const validRelationshipsToTransform = invalidRelationships.filter((n) => !invalidRelationsDuplicatesIds.includes(n.internal_id)).map((o) => o.internal_id);

  const updateToRelatedToSource = `
    if (params.invalidRelationsDuplicatesIds.contains(ctx_.source.internal_id)) {
      ctx.op = "delete";
    } else {
      for(connection in ctx._source.connections) {
        connection.role = connection.role.replace(cxt._source.entity_type, params.relToType);
      }
      ctx._source.entity_type = params.relToType;
      ctx._source.relationship_type = params.relToType;
    }
    `;

  const reindexRelationsToRelatedToQuery = {
    source: {
      index: READ_INDEX_STIX_CORE_RELATIONSHIPS,
      query: {
        bool: {
          must: { terms: { 'internal_id.keyword': [...validRelationshipsToTransform, ...invalidRelationsDuplicatesIds] } },
        }
      }
    },
    script: {
      source: updateToRelatedToSource,
      params: { relToType: RELATION_RELATED_TO, invalidRelationsDuplicatesIds }
    }
  };

  await elUpdateByQueryForMigration('[MIGRATION] Reindexing and updating non-duplicate linked-to refs', [READ_INDEX_STIX_CORE_RELATIONSHIPS], reindexRelationsToRelatedToQuery);

  const relToTypes = [RELATION_RELATED_TO, 'basic-relationship', 'stix-relationship', 'stix-core-relationship'];
  const partOfType = RELATION_PART_OF;
  const derivedFromType = RELATION_DERIVED_FROM;
  const updateRelWithRelatedToFromOrToSource = `
    if(ctx._source.fromType == params.partOfType || ctx._source.fromType == params.derivedFromType) {ctx._source.fromType=params.relToType}
    if(ctx._source.fromType == params.partOfType || ctx._source.fromType == params.derivedFromType) {ctx._source.toType=params.relToType}
    for(connection in ctx._source.connections) {
      if(connection.containsKey('internal_id') && params.invalidRelationsDuplicatesIds.contains(connection.internal_id)) { 
        ctx.op = "delete" 
      } else if(connection.types.contains(params.partOfType) || connection.types.contains(params.derivedFromType)) {
        connection.types = params.relToTypes;
      }
    }`;
  const updateRelWithRelatedToFromOrToQuery = {
    script: {
      source: updateRelWithRelatedToFromOrToSource,
      params: { partOfType, derivedFromType, relToType: RELATION_RELATED_TO, relToTypes, invalidRelationsDuplicatesIds }
    },
    query: {
      nested: {
        path: 'connections',
        query: {
          bool: {
            must: [
              { terms: { 'connections.internal_id.keyword': [...validRelationshipsToTransform, ...invalidRelationsDuplicatesIds] } }
            ]
          }
        },
      }
    }
  };
  await elUpdateByQueryForMigration('[MIGRATION] Updating relations with a related-to from or to', [READ_RELATIONSHIPS_INDICES], updateRelWithRelatedToFromOrToQuery);

  const partOf = invalidRelationships.filter((n) => !invalidRelationsDuplicatesIds.includes(n.internal_id) && n.entity_type === RELATION_PART_OF);
  const derivedFrom = invalidRelationships.filter((n) => !invalidRelationsDuplicatesIds.includes(n.internal_id) && n.entity_type === RELATION_DERIVED_FROM);
  const relPartOf = 'rel_part-of.internal_id';
  const relDerivedFrom = 'rel_derived-from.internal_id';
  const updateDenormalizedPartOfSource = `
    ArrayList partOfs = ctx._source[params.relPartOf];
    if(!ctx._source.containsKey(params.relRelatedTo)) {ctx._source[params.relRelatedTo]=[] }
    for(partOf in partOfs) {
      if(!ctx._source[params.relRelatedTo].contains(partOf)) { ctx._source[params.relRelatedTo].add(partOf) }
    }`;
  const updateDenormalizedPartOfQuery = {
    script: {
      source: updateDenormalizedPartOfSource,
      params: { relPartOf, relRelatedTo }
    },
    query: {
      bool: {
        must: [
          { terms: { 'internal_id.keyword': [...partOf.map((v) => v.fromId), ...partOf.map((v) => v.toId)] } }
        ]
      }
    },
  };

  const updateDenormalizedDerivedFromSource = `
    ArrayList derivedsFrom = ctx._source[params.relDerivedFrom];
    if(!ctx._source.containsKey(params.relRelatedTo)) {ctx._source[params.relRelatedTo]=[] }
    for(derivedFrom in derivedsFrom) {
      if(!ctx._source[params.relRelatedTo].contains(derivedFrom)) { ctx._source[params.relRelatedTo].add(derivedFrom) }
    }`;
  const updateDenormalizedDerivedFromQuery = {
    script: {
      source: updateDenormalizedDerivedFromSource,
      params: { relDerivedFrom, relRelatedTo }
    },
    query: {
      bool: {
        must: [
          { terms: { 'internal_id.keyword': [...derivedFrom.map((v) => v.fromId), ...derivedFrom.map((v) => v.toId)] } }
        ]
      }
    },
  };

  await elUpdateByQueryForMigration('[MIGRATION] Updating entities with invalid threat-actors relationships to rel_related-to', [READ_DATA_INDICES], updateDenormalizedPartOfQuery);
  await elUpdateByQueryForMigration('[MIGRATION] Updating entities with invalid threat-actors relationships to rel_related-to', [READ_DATA_INDICES], updateDenormalizedDerivedFromQuery);

  logApp.info('[MIGRATION] Update all invalid threat-actors relationships to related-to finished');
};

export const down = async (next) => {
  next();
};
