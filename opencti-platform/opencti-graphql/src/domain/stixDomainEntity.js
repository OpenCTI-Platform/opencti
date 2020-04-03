import { assoc, dissoc, map, propOr, pipe, invertObj, isNil } from 'ramda';
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
  const created = await createEntity(domainToCreate, innerType, args);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const stixDomainEntityDelete = async (stixDomainEntityId) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (!stixDomainEntity) {
    return stixDomainEntityId;
  }
  if (stixDomainEntity.entity_type === 'user' && !isNil(stixDomainEntity.external)) {
    throw new ForbiddenAccess();
  }
  return deleteEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
};
export const stixDomainEntitiesDelete = async (stixDomainEntitiesIds) => {
  return Promise.all(stixDomainEntitiesIds.map((stixDomainEntityId) => stixDomainEntityDelete(stixDomainEntityId)));
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
  const data = await createRelation(stixDomainEntityId, input, {}, 'Stix-Domain-Entity', null);
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
      toId: n,
      fromRole: input.fromRole,
      toRole: input.toRole,
      through: input.through,
    }),
    input.toIds
  );
  await createRelations(stixDomainEntityId, finalInput, {}, 'Stix-Domain-Entity', null);
  return loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity').then((entity) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, entity, user)
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
    await deleteRelationById(relationId, 'relation');
  } else if (toId) {
    if (
      stixDomainEntity.entity_type === 'user' &&
      !isNil(stixDomainEntity.external) &&
      !['tagged', 'created_by_ref', 'object_marking_refs'].includes(relationType)
    ) {
      throw new ForbiddenAccess();
    }
    await deleteRelationsByFromAndTo(stixDomainEntityId, toId, relationType, 'relation');
  } else {
    throw new Error('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, data, user);
};
export const stixDomainEntityEditField = async (user, stixDomainEntityId, input) => {
  const stixDomainEntity = await loadEntityById(stixDomainEntityId, 'Stix-Domain-Entity');
  if (stixDomainEntity.entity_type === 'user' && !isNil(stixDomainEntity.external)) {
    throw new ForbiddenAccess();
  }
  return executeWrite((wTx) => {
    return updateAttribute(stixDomainEntityId, 'Stix-Domain-Entity', input, wTx);
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
        relations.edges.map((relationEdge) => {
          const relation = relationEdge.node;
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
          };
          if (relationToCreate.fromId !== relationToCreate.toId) {
            return addStixRelation(user, relationToCreate);
          }
          return true;
        })
      );
    })
  );
  // 3. Delete entities
  await stixDomainEntitiesDelete(stixDomainEntitiesIds);
  // 4. Return entity
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
