import { assoc, dissoc, invertObj, map, pipe, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  deleteRelationsByFromAndTo,
  escape,
  escapeString,
  executeWrite,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadRelationById,
  now,
  timeSeriesEntities,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { elCount } from '../database/elasticSearch';
import { buildPagination, INDEX_STIX_OBSERVABLE } from '../database/utils';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { addIndicator } from './indicator';
import { askEnrich } from './enrichment';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { OBSERVABLE_TYPES } from '../database/stix';
import { checkObservableSyntax } from '../utils/syntax';
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { generateFileExportName, upload } from '../database/minio';
import stixObservableResolvers from '../resolvers/stixCyberObservable';
import { RELATION_OBJECT } from '../utils/idGenerator';

export const findById = (stixObservableId) => {
  return loadEntityById(stixObservableId, 'Stix-Observable');
};
export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Stix-Observable'] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Observable', args);
  return listEntities(entityTypes, ['name', 'description', 'observable_value'], finalArgs);
};

// region by elastic
export const stixObservablesNumber = (args) => ({
  count: elCount(INDEX_STIX_OBSERVABLE, args),
  total: elCount(INDEX_STIX_OBSERVABLE, dissoc('endDate', args)),
});
// endregion

// region time series
export const reportsTimeSeries = (stixObservableId, args) => {
  const filters = [
    { isRelation: true, from: 'knowledge_aggregation', to: 'so', type: RELATION_OBJECT, value: stixObservableId },
  ];
  return timeSeriesEntities('Report', filters, args);
};
export const stixObservablesTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Observable', [], args);
};
// endregion

// region mutations
export const stixObservableAskEnrichment = async (id, connectorId) => {
  const connector = await loadEntityById(connectorId, 'Connector');
  const { job, work } = await createWork(connector, 'Stix-Observable', id);
  const message = {
    work_id: work.internal_id,
    job_id: job.internal_id,
    entity_id: id,
  };
  await pushToConnector(connector, message);
  return work;
};
export const indicators = (stixObservableId) => {
  return findWithConnectedRelations(
    `match $from isa Stix-Observable; $rel(soo:$from, observables_aggregation:$to) isa observable_refs;
    $to isa Indicator;
    $from has internal_id "${escapeString(stixObservableId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const addStixObservable = async (user, stixObservable) => {
  const innerType = stixObservable.type;
  if (!OBSERVABLE_TYPES.includes(innerType.toLowerCase())) {
    throw FunctionalError(`Observable type ${innerType} is not supported.`);
  }
  const observableValue = stixObservable.observable_value.trim();
  const observableSyntaxResult = checkObservableSyntax(innerType.toLowerCase(), observableValue);
  if (observableSyntaxResult !== true) {
    throw FunctionalError(
      `Observable ${stixObservable.observable_value} of type ${innerType} is not correctly formatted.`,
      { observableSyntaxResult }
    );
  }
  const observableToCreate = pipe(
    assoc('observable_value', observableValue),
    dissoc('type'),
    dissoc('createIndicator')
  )(stixObservable);
  const created = await createEntity(user, observableToCreate, innerType);
  await askEnrich(created.id, innerType);
  // create the linked indicator
  if (stixObservable.createIndicator) {
    try {
      const pattern = await createStixPattern(created.entity_type, created.observable_value);
      if (pattern) {
        const indicatorToCreate = pipe(
          dissoc('internal_id'),
          dissoc('stix_id'),
          dissoc('observable_value'),
          assoc('name', stixObservable.observable_value),
          assoc(
            'description',
            stixObservable.description
              ? stixObservable.description
              : `Simple indicator of observable {${stixObservable.observable_value}}`
          ),
          assoc('indicator_pattern', pattern),
          assoc('pattern_type', 'stix'),
          assoc('main_observable_type', innerType),
          assoc('valid_from', stixObservable.observable_date ? stixObservable.observable_date : now()),
          assoc('observableRefs', [created.id])
        )(observableToCreate);
        await addIndicator(user, indicatorToCreate, false);
      }
    } catch (err) {
      logger.info(`Cannot create indicator`, { error: err });
    }
  }
  return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
};
export const stixObservableDelete = async (user, stixObservableId) => {
  return deleteEntityById(user, stixObservableId, 'Stix-Observable');
};
export const stixObservableAddRelation = (user, stixObservableId, input) => {
  if (!input.through) throw ForbiddenAccess();
  const finalInput = pipe(assoc('fromId', stixObservableId), assoc('fromType', 'Stix-Observable'))(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixObservableAddRelations = async (user, stixObservableId, input) => {
  const finalInput = map(
    (n) => ({
      toId: n,
      relationship_type: input.relationship_type,
    }),
    input.toIds
  );
  await createRelations(user, stixObservableId, finalInput);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((entity) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, entity, user)
  );
};
export const stixObservableEditField = (user, stixObservableId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixObservableId, 'Stix-Observable', input, wTx);
  }).then(async () => {
    const stixObservable = await loadEntityById(stixObservableId, 'Stix-Observable');
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
export const stixObservableDeleteRelation = async (
  user,
  stixObservableId,
  relationId = null,
  toId = null,
  relationType = 'stix_relation_embedded'
) => {
  const stixObservable = await loadEntityById(stixObservableId, 'Stix-Observable');
  if (!stixObservable) {
    throw FunctionalError('Cannot delete the relation, Stix-Observable cannot be found.');
  }
  if (relationId) {
    const data = await loadRelationById(relationId, 'relation');
    if (data.fromId !== stixObservable.internal_id) {
      throw ForbiddenAccess();
    }
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, stixObservableId, toId, relationType, 'relation');
  } else {
    throw FunctionalError('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixObservableId, 'Stix-Observable');
  return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixObservableCleanContext = (user, stixObservableId) => {
  delEditContext(user, stixObservableId);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((stixObservable) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return loadEntityById(stixObservableId, 'Stix-Observable').then((stixObservable) =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
// endregion

// region export
const askJobExports = async (
  format,
  entity = null,
  exportType = null,
  maxMarkingDefinition = null,
  context = null,
  listArgs = null
) => {
  const connectors = await connectorsForExport(format, true);
  // Create job for every connectors
  const haveMarking = maxMarkingDefinition && maxMarkingDefinition.length > 0;
  const maxMarkingDefinitionEntity = haveMarking ? await findMarkingDefinitionById(maxMarkingDefinition) : null;
  const workList = await Promise.all(
    map((connector) => {
      const fileName = generateFileExportName(
        format,
        connector,
        entity,
        'stix-observable',
        exportType,
        maxMarkingDefinitionEntity
      );
      return createWork(connector, 'stix-observable', entity ? entity.id : null, context, fileName).then(
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
    const stixObservablesFiltersInversed = invertObj(stixObservableResolvers.StixObservablesFilter);
    const stixObservablesOrderingInversed = invertObj(stixObservableResolvers.StixObservablesOrdering);
    finalListArgs = pipe(
      assoc(
        'filters',
        map(
          (n) => ({
            key: n.key in stixObservablesFiltersInversed ? stixObservablesFiltersInversed[n.key] : n.key,
            values: n.values,
          }),
          propOr([], 'filters', listArgs)
        )
      ),
      assoc(
        'orderBy',
        listArgs.orderBy in stixObservablesOrderingInversed
          ? stixObservablesOrderingInversed[listArgs.orderBy]
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
        entity_type: 'stix-observable',
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
export const stixObservableExportAsk = async (args) => {
  const { format, stixObservableId = null, exportType = null, maxMarkingDefinition = null, context = null } = args;
  const entity = stixObservableId ? await loadEntityById(stixObservableId, 'Stix-Observable') : null;
  const workList = await askJobExports(format, entity, exportType, maxMarkingDefinition, context, args);
  // Return the work list to do
  return map((w) => workToExportFile(w.work), workList);
};
export const stixObservableImportPush = (user, entityType = null, entityId = null, file) => {
  return upload(user, 'import', file, entityType, entityId);
};
export const stixObservableExportPush = async (user, entityId = null, file, context = null, listArgs = null) => {
  // Upload the document in minio
  await upload(user, 'export', file, 'stix-observable', entityId, context, listArgs);
  return true;
};
