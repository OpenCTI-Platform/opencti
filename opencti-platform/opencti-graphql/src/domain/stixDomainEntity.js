import { assoc, dissoc, map, propOr, pipe, invertObj, isNil, pathOr } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  escape,
  executeWrite,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  timeSeriesEntities,
  updateAttribute,
  deleteRelationsByFromAndTo,
  loadRelationById,
} from '../database/grakn';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { elCount } from '../database/elasticSearch';
import { generateFileExportName, upload } from '../database/minio';
import { connectorsForExport } from './connector';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import stixDomainEntityResolvers from '../resolvers/stixDomainEntity';
import { findAll as findAllStixRelations, addStixRelation } from './stixRelation';
import { ForbiddenAccess } from '../config/errors';
import { INDEX_STIX_ENTITIES, TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';
import { createdByRef, markingDefinitions, killChainPhases, reports } from './stixEntity';

export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Stix-Domain-Entity'] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Domain-Entity', args);
  let data = await listEntities(entityTypes, ['name', 'alias'], finalArgs);
  data = assoc(
    'edges',
    map(
      (n) => ({
        cursor: n.cursor,
        node: pipe(dissoc('user_email'), dissoc('password'))(n.node),
        relation: n.relation,
      }),
      data.edges
    ),
    data
  );
  return data;
};

// eslint-disable-next-line no-unused-vars
export const findAllDuplicates = (args) => {
  // TODO @Sam, implement findAllDuplicates
  // const noTypes = !args.types || args.types.length === 0;
  // const entityTypes = noTypes ? ['Stix-Domain-Entity'] : args.types;
  return [];
};
export const findById = async (stixDomainEntityId) => {
  let data;
  if (stixDomainEntityId.match(/[a-z-]+--[\w-]{36}/g)) {
    data = await loadEntityByStixId(stixDomainEntityId, 'Stix-Domain-Entity');
  } else {
    data = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  }
  if (!data) {
    return data;
  }
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};

// region time series
export const reportsTimeSeries = (stixDomainEntityId, args) => {
  const filters = [
    { isRelation: true, from: 'knowledge_aggregation', to: 'so', type: 'object_refs', value: stixDomainEntityId },
  ];
  return timeSeriesEntities('Report', filters, args);
};
export const stixDomainEntitiesTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Domain-Entity', [], args);
};

export const stixDomainEntitiesNumber = (args) => ({
  count: elCount(INDEX_STIX_ENTITIES, args),
  total: elCount(INDEX_STIX_ENTITIES, dissoc('endDate', args)),
});
// endregion

// region export
const askJobExports = async (
  format,
  entity = null,
  type = null,
  exportType = null,
  maxMarkingDefinition = null,
  context = null,
  listArgs = null
) => {
  const connectors = await connectorsForExport(format, true);
  // Create job for every connectors
  const haveMarking = maxMarkingDefinition && maxMarkingDefinition.length > 0;
  const maxMarkingDefinitionEntity = haveMarking ? await findMarkingDefinitionById(maxMarkingDefinition) : null;
  const finalEntityType = entity ? entity.entity_type : type.toLowerCase();
  const workList = await Promise.all(
    map((connector) => {
      const fileName = generateFileExportName(
        format,
        connector,
        entity,
        finalEntityType,
        exportType,
        maxMarkingDefinitionEntity
      );
      return createWork(connector, finalEntityType, entity ? entity.id : null, context, fileName).then(
        ({ work, job }) => ({
          connector,
          job,
          work,
        })
      );
    }, connectors)
  );
  let finalListArgs = listArgs;
  if (listArgs !== null) {
    const stixDomainEntitiesFiltersInversed = invertObj(stixDomainEntityResolvers.StixDomainEntitiesFilter);
    const stixDomainEntitiesOrderingInversed = invertObj(stixDomainEntityResolvers.StixDomainEntitiesOrdering);
    finalListArgs = pipe(
      assoc(
        'filters',
        map(
          (n) => ({
            key: n.key in stixDomainEntitiesFiltersInversed ? stixDomainEntitiesFiltersInversed[n.key] : n.key,
            values: n.values,
          }),
          propOr([], 'filters', listArgs)
        )
      ),
      assoc(
        'orderBy',
        listArgs.orderBy in stixDomainEntitiesOrderingInversed
          ? stixDomainEntitiesOrderingInversed[listArgs.orderBy]
          : listArgs.orderBy
      )
    )(listArgs);
  }
  // Send message to all correct connectors queues
  await Promise.all(
    map((data) => {
      const { connector, job, work } = data;
      const message = {
        work_id: work.internal_id_key, // work(id)
        job_id: job.internal_id_key, // job(id)
        max_marking_definition: maxMarkingDefinition && maxMarkingDefinition.length > 0 ? maxMarkingDefinition : null, // markingDefinition(id)
        export_type: exportType, // for entity, simple or full / for list, withArgs / withoutArgs
        entity_type: entity ? entity.entity_type : type, // report, threat, ...
        entity_id: entity ? entity.id : null, // report(id), thread(id), ...
        list_args: finalListArgs,
        file_context: work.work_context,
        file_name: work.work_file, // Base path for the upload
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
// endregion

// region mutation
/**
 * Create export element waiting for completion
 * @param args
 * @returns {*}
 */
export const stixDomainEntityExportAsk = async (args) => {
  const {
    format,
    type = null,
    stixDomainEntityId = null,
    exportType = null,
    maxMarkingDefinition = null,
    context = null,
  } = args;
  const entity = stixDomainEntityId ? await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity') : null;
  const workList = await askJobExports(format, entity, type, exportType, maxMarkingDefinition, context, args);
  // Return the work list to do
  return map((w) => workToExportFile(w.work), workList);
};
export const stixDomainEntityImportPush = (user, entityType = null, entityId = null, file) => {
  return upload(user, 'import', file, entityType, entityId);
};
export const stixDomainEntityExportPush = async (
  user,
  entityType = null,
  entityId = null,
  file,
  context = null,
  listArgs = null
) => {
  // Upload the document in minio
  await upload(user, 'export', file, entityType, entityId, context, listArgs);
  return true;
};
export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const innerType = stixDomainEntity.type;
  const domainToCreate = dissoc('type', stixDomainEntity);
  let args = {};
  if (
    innerType.toLowerCase() === 'sector' ||
    innerType.toLowerCase() === 'organization' ||
    innerType.toLowerCase() === 'user' ||
    innerType.toLowerCase() === 'region' ||
    innerType.toLowerCase() === 'country' ||
    innerType.toLowerCase() === 'city'
  ) {
    args = { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' };
  }
  const created = await createEntity(user, domainToCreate, innerType, args);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const stixDomainEntityDelete = async (user, stixDomainEntityId) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (!stixDomainEntity) {
    return stixDomainEntityId;
  }
  if (stixDomainEntity.entity_type === 'user' && !isNil(stixDomainEntity.external)) {
    throw new ForbiddenAccess();
  }
  return deleteEntityById(user, stixDomainEntityId, 'Stix-Domain-Entity');
};
export const stixDomainEntitiesDelete = async (user, stixDomainEntitiesIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixDomainEntitiesIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await stixDomainEntityDelete(user, stixDomainEntitiesIds[i]);
  }
  return stixDomainEntitiesIds;
};

export const stixDomainEntityAddRelation = async (user, stixDomainEntityId, input) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (
    (stixDomainEntity.entity_type === 'user' &&
      !isNil(stixDomainEntity.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(input.through)) ||
    !input.through
  ) {
    throw new ForbiddenAccess();
  }
  const finalInput = assoc('fromType', 'Stix-Domain-Entity', input);
  const data = await createRelation(user, stixDomainEntityId, finalInput);
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const stixDomainEntityAddRelations = async (user, stixDomainEntityId, input) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (
    (stixDomainEntity.entity_type === 'user' &&
      !isNil(stixDomainEntity.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(input.through)) ||
    !input.through
  ) {
    throw new ForbiddenAccess();
  }
  const finalInput = map(
    (n) => ({
      fromType: 'Stix-Domain-Entity',
      fromRole: input.fromRole,
      toId: n,
      toRole: input.toRole,
      through: input.through,
    }),
    input.toIds
  );
  await createRelations(user, stixDomainEntityId, finalInput);
  return loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity').then((entity) =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, entity, user)
  );
};
export const stixDomainEntityDeleteRelation = async (
  user,
  stixDomainEntityId,
  relationId = null,
  toId = null,
  relationType = 'stix_relation_embedded'
) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (!stixDomainEntity) {
    throw new Error('Cannot delete the relation, Stix-Domain-Entity cannot be found.');
  }
  if (relationId) {
    const data = await loadRelationById(relationId, 'relation');
    if (
      data.fromId !== stixDomainEntity.grakn_id ||
      (stixDomainEntity.entity_type === 'user' &&
        !isNil(stixDomainEntity.external) &&
        !['tagged', 'created_by_ref', 'object_marking_refs'].includes(data.relationship_type))
    ) {
      throw new ForbiddenAccess();
    }
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    if (
      stixDomainEntity.entity_type === 'user' &&
      !isNil(stixDomainEntity.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(relationType)
    ) {
      throw new ForbiddenAccess();
    }
    await deleteRelationsByFromAndTo(user, stixDomainEntityId, toId, relationType, 'relation');
  } else {
    throw new Error('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const stixDomainEntityEditField = async (user, stixDomainEntityId, input) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (!stixDomainEntity) {
    throw new Error('Cannot edit field, Stix-Domain-Entity cannot be found.');
  }
  if (stixDomainEntity.entity_type === 'user' && !isNil(stixDomainEntity.external)) {
    throw new ForbiddenAccess();
  }
  return executeWrite((wTx) => {
    return updateAttribute(user, stixDomainEntityId, 'Stix-Domain-Entity', input, wTx);
  }).then(async () => {
    const stixDomain = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomain, user);
  });
};
export const stixDomainEntityMerge = async (user, stixDomainEntityId, stixDomainEntitiesIds, alias) => {
  // 1. Update aliases
  await stixDomainEntityEditField(user, stixDomainEntityId, { key: 'alias', value: alias });
  // 2. Copy the relationships
  await Promise.all(
    stixDomainEntitiesIds.map(async (id) => {
      const relations = await findAllStixRelations({ fromId: id, forceNatural: true });
      return Promise.all(
        relations.edges.map(async (relationEdge) => {
          const relation = relationEdge.node;
          const relationCreatedByRef = await createdByRef(relation.id);
          const relationMarkingDefinitions = await markingDefinitions(relation.id);
          const relationkillChainPhases = await killChainPhases(relation.id);
          const relationReports = await reports(relation.id);
          const relationToCreate = {
            fromId: id === relation.fromInternalId ? stixDomainEntityId : relation.fromInternalId,
            fromRole: relation.fromRole,
            toId: id === relation.toInternalId ? stixDomainEntityId : relation.toInternalId,
            toRole: relation.toRole,
            relationship_type: relation.relationship_type,
            weight: relation.weight,
            description: relation.description,
            role_played: relation.role_played,
            first_seen: relation.first_seen,
            last_seen: relation.last_seen,
            created: relation.created,
            modified: relation.modified,
            createdByRef: pathOr(null, ['node', 'id'], relationCreatedByRef),
            markingDefinitions: map((n) => n.node.id, relationMarkingDefinitions.edges),
            killChainPhases: map((n) => n.node.id, relationkillChainPhases.edges),
          };
          if (relationToCreate.fromId !== relationToCreate.toId) {
            const newRelation = await addStixRelation(user, relationToCreate);
            await Promise.all(
              relationReports.edges.map((report) => {
                return stixDomainEntityAddRelation(user, report.node.id, {
                  fromRole: 'knowledge_aggregation',
                  toId: newRelation.internal_id_key,
                  toRole: 'so',
                  through: 'object_refs',
                });
              })
            );
            return true;
          }
          return true;
        })
      );
    })
  );
  // 3. Copy reports refs
  await Promise.all(
    stixDomainEntitiesIds.map(async (id) => {
      const stixDomainEntityReports = await reports(id);
      return Promise.all(
        stixDomainEntityReports.edges.map((reportEdge) => {
          const report = reportEdge.node;
          return stixDomainEntityAddRelation(user, report.id, {
            fromRole: 'knowledge_aggregation',
            toId: stixDomainEntityId,
            toRole: 'so',
            through: 'object_refs',
          });
        })
      );
    })
  );

  // 4. Delete entities
  await stixDomainEntitiesDelete(user, stixDomainEntitiesIds);
  // 5. Return entity
  return loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity').then((stixDomainEntity) =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};
// endregion

// region context
export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity').then((stixDomainEntity) =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};
export const stixDomainEntityEditContext = (user, stixDomainEntityId, input) => {
  setEditContext(user, stixDomainEntityId, input);
  return loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity').then((stixDomainEntity) =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};
// endregion
