import { assoc, includes, dissoc, invertObj, isNil, map, pathOr, pipe, propOr } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  deleteRelationsByFromAndTo,
  escape,
  executeWrite,
  listEntities,
  loadEntityById,
  loadRelationById,
  timeSeriesEntities,
  updateAttribute,
} from '../database/grakn';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { elCount } from '../database/elasticSearch';
import { generateFileExportName, upload } from '../database/minio';
import { connectorsForExport } from './connector';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import stixDomainObjectResolvers from '../resolvers/stixDomainObject';
import { noteContainsStixCoreObjectOrStixRelationship } from './note';
import { reportContainsStixCoreObjectOrStixRelationship } from './report';
import { addStixCoreRelationship, findAll as findAllStixRelations } from './stixCoreRelationship';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { createdBy, killChainPhases, markingDefinitions, reports, notes } from './stixCoreObject';
import {
  ENTITY_TYPE_USER,
  RELATION_CREATED_BY,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
} from '../utils/idGenerator';

export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? [ABSTRACT_STIX_CORE_OBJECT] : args.types;
  const finalArgs = assoc('parentType', ABSTRACT_STIX_DOMAIN_OBJECT, args);
  let data = await listEntities(entityTypes, ['name', 'aliases'], finalArgs);
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
  // const entityTypes = noTypes ? ['Stix-Domain-Object'] : args.types;
  return [];
};

export const findById = async (stixDomainObjectId) => {
  let data = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  if (!data) return data;
  data = pipe(dissoc('user_email'), dissoc('password'))(data);
  return data;
};

// region time series
export const reportsTimeSeries = (stixDomainObjectId, args) => {
  const filters = [
    { isRelation: true, from: 'knowledge_aggregation', to: 'so', type: RELATION_OBJECT, value: stixDomainObjectId },
  ];
  return timeSeriesEntities('Report', filters, args);
};
export const stixDomainObjectsTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Domain-Object', [], args);
};

export const stixDomainObjectsNumber = (args) => ({
  count: elCount(INDEX_STIX_DOMAIN_OBJECTS, args),
  total: elCount(INDEX_STIX_DOMAIN_OBJECTS, dissoc('endDate', args)),
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
  const finalEntityType = entity ? entity.entity_type : type;
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
    const stixDomainObjectsFiltersInversed = invertObj(stixDomainObjectResolvers.stixDomainObjectsFilter);
    const stixDomainObjectsOrderingInversed = invertObj(stixDomainObjectResolvers.stixDomainObjectsOrdering);
    finalListArgs = pipe(
      assoc(
        'filters',
        map(
          (n) => ({
            key: n.key in stixDomainObjectsFiltersInversed ? stixDomainObjectsFiltersInversed[n.key] : n.key,
            values: n.values,
          }),
          propOr([], 'filters', listArgs)
        )
      ),
      assoc(
        'orderBy',
        listArgs.orderBy in stixDomainObjectsOrderingInversed
          ? stixDomainObjectsOrderingInversed[listArgs.orderBy]
          : listArgs.orderBy
      )
    )(listArgs);
  }
  // Send message to all correct connectors queues
  await Promise.all(
    map((data) => {
      const { connector, job, work } = data;
      const message = {
        work_id: work.internal_id, // work(id)
        job_id: job.internal_id, // job(id)
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
export const stixDomainObjectExportAsk = async (args) => {
  const {
    format,
    type = null,
    stixDomainObjectId = null,
    exportType = null,
    maxMarkingDefinition = null,
    context = null,
  } = args;
  const entity = stixDomainObjectId ? await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object') : null;
  const workList = await askJobExports(format, entity, type, exportType, maxMarkingDefinition, context, args);
  // Return the work list to do
  return map((w) => workToExportFile(w.work), workList);
};

export const stixDomainObjectImportPush = (user, entityType = null, entityId = null, file) => {
  return upload(user, 'import', file, entityType, entityId);
};

export const stixDomainObjectExportPush = async (
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

export const addstixDomainObject = async (user, stixDomainObject) => {
  const innerType = stixDomainObject.type;
  const created = await createEntity(user, dissoc('type', stixDomainObject), innerType);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};

export const stixDomainObjectDelete = async (user, stixDomainObjectId) => {
  const stixDomainObject = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  if (!stixDomainObject) {
    return stixDomainObjectId;
  }
  if (stixDomainObject.entity_type === 'user' && !isNil(stixDomainObject.external)) {
    throw ForbiddenAccess();
  }
  return deleteEntityById(user, stixDomainObjectId, 'Stix-Domain-Object');
};

export const stixDomainObjectsDelete = async (user, stixDomainObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixDomainObjectsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await stixDomainObjectDelete(user, stixDomainObjectsIds[i]);
  }
  return stixDomainObjectsIds;
};

export const stixDomainObjectAddRelation = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  const isUserType = stixDomainObject.entity_type === 'user';
  if (
    (isUserType &&
      !isNil(stixDomainObject.external) &&
      ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(input.relationship_type)) ||
    !input.relationship_type
  ) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixDomainObjectId, input);
  const data = await createRelation(user, finalInput);
  return notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, data, user);
};
export const stixDomainObjectAddRelations = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  if (
    (stixDomainObject.entity_type === 'user' &&
      !isNil(stixDomainObject.external) &&
      ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(input.relationship_type)) ||
    !input.relationship_type
  ) {
    throw ForbiddenAccess();
  }
  const finalInput = map(
    (n) => ({
      fromType: 'Stix-Domain-Object',
      toId: n,
      relationship_type: input.relationship_type,
    }),
    input.toIds
  );
  await createRelations(user, stixDomainObjectId, finalInput);
  return loadEntityById(stixDomainObjectId, 'Stix-Domain-Object').then((entity) =>
    notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, entity, user)
  );
};
export const stixDomainObjectDeleteRelation = async (
  user,
  stixDomainObjectId,
  relationId = null,
  toId = null,
  relationship_type = 'stix_relation_embedded'
) => {
  const stixDomainObject = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  if (!stixDomainObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Domain-Object cannot be found.');
  }
  if (relationId) {
    const data = await loadRelationById(relationId, 'relation');
    if (
      data.fromId !== stixDomainObject.internal_id ||
      (stixDomainObject.entity_type === ENTITY_TYPE_USER &&
      !isNil(stixDomainObject.external) && // TODO JRI ASK @SAM
        ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(data.entity_type))
    ) {
      throw ForbiddenAccess();
    }
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    if (
      stixDomainObject.entity_type === 'user' &&
      !isNil(stixDomainObject.external) &&
      ![RELATION_OBJECT_LABEL, RELATION_CREATED_BY, RELATION_OBJECT_MARKING].includes(relationship_type)
    ) {
      throw ForbiddenAccess();
    }
    await deleteRelationsByFromAndTo(user, stixDomainObjectId, toId, relationship_type, 'relation');
  } else {
    throw FunctionalError('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  return notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, data, user);
};
export const stixDomainObjectEditField = async (user, stixDomainObjectId, input) => {
  const stixDomainObject = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
  if (!stixDomainObject) {
    throw FunctionalError('Cannot edit field, Stix-Domain-Object cannot be found.');
  }
  if (stixDomainObject.entity_type === 'user' && !isNil(stixDomainObject.external)) {
    throw ForbiddenAccess();
  }
  return executeWrite((wTx) => {
    return updateAttribute(user, stixDomainObjectId, 'Stix-Domain-Object', input, wTx);
  }).then(async () => {
    const stixDomain = await loadEntityById(stixDomainObjectId, 'Stix-Domain-Object');
    return notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, stixDomain, user);
  });
};
export const stixDomainObjectMerge = async (user, stixDomainObjectId, stixDomainObjectsIds, alias) => {
  // 1. Update aliases
  await stixDomainObjectEditField(user, stixDomainObjectId, { key: 'alias', value: alias });
  // 2. Copy the relationships
  await Promise.all(
    stixDomainObjectsIds.map(async (id) => {
      const relations = await findAllStixRelations({ fromId: id, forceNatural: true });
      return Promise.all(
        relations.edges.map(async (relationEdge) => {
          const relation = relationEdge.node;
          const relationCreatedBy = await createdBy(relation.id);
          const relationMarkingDefinitions = await markingDefinitions(relation.id);
          const relationkillChainPhases = await killChainPhases(relation.id);
          const relationReports = await reports(relation.id);
          const relationNotes = await notes(relation.id);
          const relationToCreate = {
            fromId: relation.fromInternalId,
            fromRole: relation.fromRole,
            toId: relation.toInternalId,
            toRole: relation.toRole,
            relationship_type: relation.entity_type,
            confidence: relation.confidence,
            description: relation.description,
            first_seen: relation.first_seen,
            last_seen: relation.last_seen,
            created: relation.created,
            modified: relation.modified,
            createdBy: pathOr(null, ['node', 'id'], relationCreatedBy),
            markingDefinitions: map((n) => n.node.id, relationMarkingDefinitions.edges),
            killChainPhases: map((n) => n.node.id, relationkillChainPhases.edges),
          };
          if (relationToCreate.fromId !== relationToCreate.toId) {
            const newRelation = await addStixCoreRelationship(user, relationToCreate);
            await Promise.all(
              relationReports.edges.map((report) => {
                return stixDomainObjectAddRelation(user, report.node.id, {
                  toId: newRelation.internal_id,
                  relationship_type: RELATION_OBJECT,
                });
              })
            );
            await Promise.all(
              relationNotes.edges.map((note) => {
                return stixDomainObjectAddRelation(user, note.node.id, {
                  toId: newRelation.internal_id,
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
    stixDomainObjectsIds.map(async (id) => {
      const stixDomainObjectReports = await reports(id);
      return Promise.all(
        stixDomainObjectReports.edges.map(async (reportEdge) => {
          const report = reportEdge.node;
          const alreadyInReport = await reportContainsStixCoreObjectOrStixRelationship(report.id, stixDomainObjectId);
          if (!alreadyInReport) {
            return stixDomainObjectAddRelation(user, report.id, {
              toId: stixDomainObjectId,
              relationship_type: RELATION_OBJECT,
            });
          }
          return true;
        })
      );
    })
  );

  // 4. Copy notes refs
  await Promise.all(
    stixDomainObjectsIds.map(async (id) => {
      const stixDomainObjectNotes = await notes(id);
      return Promise.all(
        stixDomainObjectNotes.edges.map(async (noteEdge) => {
          const note = noteEdge.node;
          const alreadyInNote = await noteContainsStixCoreObjectOrStixRelationship(note.id, stixDomainObjectId);
          if (!alreadyInNote) {
            return stixDomainObjectAddRelation(user, note.id, {
              toId: stixDomainObjectId,
              relationship_type: RELATION_OBJECT,
            });
          }
          return true;
        })
      );
    })
  );

  // 5. Delete entities
  await stixDomainObjectsDelete(user, stixDomainObjectsIds);
  // 6. Return entity
  return loadEntityById(stixDomainObjectId, 'Stix-Domain-Object').then((stixDomainObject) =>
    notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, stixDomainObject, user)
  );
};
// endregion

// region context
export const stixDomainObjectCleanContext = (user, stixDomainObjectId) => {
  delEditContext(user, stixDomainObjectId);
  return loadEntityById(stixDomainObjectId, 'Stix-Domain-Object').then((stixDomainObject) =>
    notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, stixDomainObject, user)
  );
};
export const stixDomainObjectEditContext = (user, stixDomainObjectId, input) => {
  setEditContext(user, stixDomainObjectId, input);
  return loadEntityById(stixDomainObjectId, 'Stix-Domain-Object').then((stixDomainObject) =>
    notify(BUS_TOPICS.stixDomainObject.EDIT_TOPIC, stixDomainObject, user)
  );
};
// endregion
