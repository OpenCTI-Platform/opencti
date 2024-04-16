import { logApp } from '../config/conf';
import { elDeleteByQueryForMigration, elList, elRawCount, elReindexByQueryForMigration, elUpdateByQueryForMigration } from '../database/engine';
import {
  INDEX_STIX_CORE_RELATIONSHIPS,
  READ_DATA_INDICES,
  INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES,
  READ_INDEX_STIX_CORE_RELATIONSHIPS
} from '../database/utils';
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Update all linked-to refs to related-to rels');

  const linkedToType = 'x_opencti_linked-to';
  const relLinkedTo = `rel_${linkedToType}.internal_id`;
  const relRelatedTo = `rel_${RELATION_RELATED_TO}.internal_id`;

  // We get all current linked-to relations: will be used to check for duplicates in linked-to to related-to migration
  const linkedToRefRelations = await elList(context, SYSTEM_USER, READ_INDEX_STIX_META_RELATIONSHIPS, { types: [linkedToType] });

  // If no linked-to refs exist, we can skip the migration process
  if (linkedToRefRelations.length === 0) {
    logApp.info('[MIGRATION] Update all linked-to refs to related-to rels finished: no linked-to to migrate');
    next();
    return;
  }
  logApp.info(`[MIGRATION] Update all linked-to refs to related-to rels: ${linkedToRefRelations.length} linked-to to migrate`);

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

  const linkedToRefRelationsDuplicatesIds = [];
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < linkedToRefRelations.length; i++) {
    const linkedToRef = linkedToRefRelations[i];
    const hasDuplicate = await searchRelatedToDuplicateFn(linkedToRef.fromId, linkedToRef.toId);
    if (hasDuplicate) linkedToRefRelationsDuplicatesIds.push(linkedToRef.internal_id);
  }

  // First, we reindex all linked-to meta refs to core rel index, updating all linked-to refs to related-to rel in the process
  // During the process, we check for duplicates with existing relatedTo rel: if on already exists, we skip this element for the reindexing
  const reindexLinkedToToRelatedToSource = `
    String fromId;
    String toId;
    ctx._source.entity_type = params.relToType;
    ctx._source.relationship_type = params.relToType;
    ctx._source.parent_types = params.relToParentTypes;
    ctx._source.standard_id = ctx._source.standard_id.replace("relationship-meta--", "relationship--");
    for(connection in ctx._source.connections) {
      connection.role = connection.role.replace(params.linkedToType, params.relToType);
    }
    `;
  const relToParentTypes = ['basic-relationship', 'stix-relationship', 'stix-core-relationship'];

  const reindexLinkedToToRelatedToQuery = {
    source: {
      index: INDEX_STIX_META_RELATIONSHIPS,
      query: {
        bool: {
          must: { term: { 'entity_type.keyword': { value: linkedToType } } },
          must_not: { terms: { 'internal_id.keyword': linkedToRefRelationsDuplicatesIds } }
        }
      }
    },
    dest: {
      index: INDEX_STIX_CORE_RELATIONSHIPS
    },
    script: {
      source: reindexLinkedToToRelatedToSource,
      params: { linkedToType, relToType: RELATION_RELATED_TO, relToParentTypes }
    }
  };

  await elReindexByQueryForMigration('[MIGRATION] Reindexing and updating non-duplicate linked-to refs', null, reindexLinkedToToRelatedToQuery);

  // Then, We need to update all rel that had a linked-to ref as from or to
  // If linked to was a duplicate, we need to delete the relation instead
  const relToTypes = [RELATION_RELATED_TO, 'basic-relationship', 'stix-relationship', 'stix-core-relationship'];
  const updateRelWithLinkedToFromOrToSource = `
    if(ctx._source.fromType == params.linkedToType) {ctx._source.fromType=params.relToType}
    if(ctx._source.toType == params.linkedToType) {ctx._source.toType=params.relToType}
    for(connection in ctx._source.connections) {
      if(connection.containsKey('internal_id') && params.linkedToRefRelationsDuplicatesIds.contains(connection.internal_id)) { 
        ctx.op = "delete" 
      } else if(connection.types.contains(params.linkedToType)) {
        connection.types = params.relToTypes;
        connection.name = connection.name.replace("relationship-meta--", "relationship--");
      }
    }`;
  const updateRelWithLinkedToFromOrToQuery = {
    script: {
      source: updateRelWithLinkedToFromOrToSource,
      params: { linkedToType, relToType: RELATION_RELATED_TO, relToTypes, linkedToRefRelationsDuplicatesIds }
    },
    query: {
      nested: {
        path: 'connections',
        query: {
          bool: {
            must: [
              { term: { 'connections.types.keyword': { value: linkedToType } } }
            ]
          }
        },
      }
    }
  };
  await elUpdateByQueryForMigration('[MIGRATION] Updating relations with a linked-to from or to', [READ_RELATIONSHIPS_INDICES], updateRelWithLinkedToFromOrToQuery);

  // Then we need to move all denormalized linked-to rel in objects to related-to (if id is not already in related-to)
  const updateDenormalizedLinkedToSource = `
    ArrayList linkedTos = ctx._source[params.relLinkedTo];
    if(!ctx._source.containsKey(params.relRelatedTo)) {ctx._source[params.relRelatedTo]=[] }
    for(linkedTo in linkedTos) {
      if(!ctx._source[params.relRelatedTo].contains(linkedTo)) { ctx._source[params.relRelatedTo].add(linkedTo) }
    }
    ctx._source.remove(params.relLinkedTo)`;
  const updateDenormalizedLinkedToQuery = {
    script: {
      source: updateDenormalizedLinkedToSource,
      params: { relLinkedTo, relRelatedTo }
    },
    query: {
      exists: {
        field: relLinkedTo
      }
    },
  };

  await elUpdateByQueryForMigration('[MIGRATION] Updating entities with rel_linked-to to rel_related-to', [READ_DATA_INDICES], updateDenormalizedLinkedToQuery);

  // Finally, we delete all original linked-to refs in meta rel index

  await elDeleteByQueryForMigration(
    '[MIGRATION] Deleting all linked-to refs',
    [READ_INDEX_STIX_META_RELATIONSHIPS],
    {
      query: {
        term: { 'entity_type.keyword': { value: linkedToType } }
      }
    }
  );

  logApp.info('[MIGRATION] Update all linked-to refs to related-to rels finished');

  next();
};

export const down = async (next) => {
  next();
};
