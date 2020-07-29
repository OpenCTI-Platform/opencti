import { assoc, dissoc, invertObj, map, pipe, propOr, filter } from 'ramda';
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
import { buildPagination, INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { addIndicator } from './indicator';
import { askEnrich } from './enrichment';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { checkObservableSyntax } from '../utils/syntax';
import { connectorsForExport } from './connector';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { generateFileExportName, upload } from '../database/minio';
import stixCyberObservableResolvers from '../resolvers/stixCyberObservable';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, isStixCyberObservable, RELATION_OBJECT } from '../utils/idGenerator';

export const findById = (stixCyberObservableId) => {
  return loadEntityById(stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
};

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixCyberObservable(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CYBER_OBSERVABLE);
  }
  return listEntities(types, ['standard_id'], args);
};

// region by elastic
export const stixCyberObservablesNumber = (args) => ({
  count: elCount(INDEX_STIX_CYBER_OBSERVABLES, args),
  total: elCount(INDEX_STIX_CYBER_OBSERVABLES, dissoc('endDate', args)),
});
// endregion

// region time series
export const reportsTimeSeries = (stixCyberObservableId, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: stixCyberObservableId }];
  return timeSeriesEntities('Report', filters, args);
};

export const stixCyberObservablesTimeSeries = (args) => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Observable', [], args);
};
// endregion

// region mutations
export const stixCyberObservableAskEnrichment = async (id, connectorId) => {
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

export const indicators = (stixCyberObservableId) => {
  return findWithConnectedRelations(
    `match $from isa Stix-Observable; $rel(soo:$from, observables_aggregation:$to) isa observable_refs;
    $to isa Indicator;
    $from has internal_id "${escapeString(stixCyberObservableId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const observableValue = (stixCyberObservable) => {
  return stixCyberObservable.value;
};

export const addStixCyberObservable = async (user, stixCyberObservable) => {
  if (!isStixCyberObservable(stixCyberObservable.type)) {
    throw FunctionalError(`Observable type ${stixCyberObservable.type} is not supported.`);
  }
  const observableValue = stixCyberObservable.observable_value.trim();
  const observableSyntaxResult = checkObservableSyntax(stixCyberObservable.type.toLowerCase(), observableValue);
  if (observableSyntaxResult !== true) {
    throw FunctionalError(
      `Observable ${stixCyberObservable.observable_value} of type ${stixCyberObservable.type} is not correctly formatted.`,
      { observableSyntaxResult }
    );
  }
  const observableToCreate = pipe(
    assoc('observable_value', observableValue),
    dissoc('type'),
    dissoc('createIndicator')
  )(stixCyberObservable);
  const created = await createEntity(user, observableToCreate, stixCyberObservable.type);
  await askEnrich(created.id, stixCyberObservable.type);
  // create the linked indicator
  if (stixCyberObservable.createIndicator) {
    try {
      const pattern = await createStixPattern(created.entity_type, created.observable_value);
      if (pattern) {
        const indicatorToCreate = pipe(
          dissoc('internal_id'),
          dissoc('stix_id'),
          dissoc('observable_value'),
          assoc('name', stixCyberObservable.observable_value),
          assoc(
            'description',
            stixCyberObservable.description
              ? stixCyberObservable.description
              : `Simple indicator of observable {${stixCyberObservable.observable_value}}`
          ),
          assoc('indicator_pattern', pattern),
          assoc('pattern_type', 'stix'),
          assoc('main_observable_type', stixCyberObservable.type),
          assoc('valid_from', stixCyberObservable.observable_date ? stixCyberObservable.observable_date : now()),
          assoc('observableRefs', [created.id])
        )(observableToCreate);
        await addIndicator(user, indicatorToCreate, false);
      }
    } catch (err) {
      logger.info(`Cannot create indicator`, { error: err });
    }
  }
  return notify(BUS_TOPICS.StixCyberObservable.ADDED_TOPIC, created, user);
};

export const stixCyberObservableDelete = async (user, stixCyberObservableId) => {
  return deleteEntityById(user, stixCyberObservableId, 'Stix-Observable');
};

export const stixCyberObservableAddRelation = (user, stixCyberObservableId, input) => {
  if (!input.through) throw ForbiddenAccess();
  const finalInput = pipe(assoc('fromId', stixCyberObservableId), assoc('fromType', 'Stix-Observable'))(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCyberObservableAddRelations = async (user, stixCyberObservableId, input) => {
  const finalInput = map(
    (n) => ({
      toId: n,
      relationship_type: input.relationship_type,
    }),
    input.toIds
  );
  await createRelations(user, stixCyberObservableId, finalInput);
  return loadEntityById(stixCyberObservableId, 'Stix-Observable').then((entity) =>
    notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, entity, user)
  );
};

export const stixCyberObservableEditField = (user, stixCyberObservableId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixCyberObservableId, 'Stix-Observable', input, wTx);
  }).then(async () => {
    const stixCyberObservable = await loadEntityById(stixCyberObservableId, 'Stix-Observable');
    return notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, stixCyberObservable, user);
  });
};

export const stixCyberObservableDeleteRelation = async (
  user,
  stixCyberObservableId,
  relationId = null,
  toId = null,
  relationship_type = 'stix_relation_embedded'
) => {
  const stixCyberObservable = await loadEntityById(stixCyberObservableId, 'Stix-Observable');
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot delete the relation, Stix-Observable cannot be found.');
  }
  if (relationId) {
    const data = await loadRelationById(relationId, 'relation');
    if (data.fromId !== stixCyberObservable.internal_id) {
      throw ForbiddenAccess();
    }
    await deleteRelationById(user, relationId, 'relation');
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, stixCyberObservableId, toId, relationship_type, 'relation');
  } else {
    throw FunctionalError('Cannot delete the relation, missing relationId or toId');
  }
  const data = await loadEntityById(stixCyberObservableId, 'Stix-Observable');
  return notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixCyberObservableCleanContext = (user, stixCyberObservableId) => {
  delEditContext(user, stixCyberObservableId);
  return loadEntityById(stixCyberObservableId, 'Stix-Observable').then((stixCyberObservable) =>
    notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, stixCyberObservable, user)
  );
};

export const stixCyberObservableEditContext = (user, stixCyberObservableId, input) => {
  setEditContext(user, stixCyberObservableId, input);
  return loadEntityById(stixCyberObservableId, 'Stix-Observable').then((stixCyberObservable) =>
    notify(BUS_TOPICS.StixCyberObservable.EDIT_TOPIC, stixCyberObservable, user)
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
    const stixCyberObservablesFiltersInversed = invertObj(stixCyberObservableResolvers.StixCyberObservablesFilter);
    const stixCyberObservablesOrderingInversed = invertObj(stixCyberObservableResolvers.StixCyberObservablesOrdering);
    finalListArgs = pipe(
      assoc(
        'filters',
        map(
          (n) => ({
            key: n.key in stixCyberObservablesFiltersInversed ? stixCyberObservablesFiltersInversed[n.key] : n.key,
            values: n.values,
          }),
          propOr([], 'filters', listArgs)
        )
      ),
      assoc(
        'orderBy',
        listArgs.orderBy in stixCyberObservablesOrderingInversed
          ? stixCyberObservablesOrderingInversed[listArgs.orderBy]
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
export const stixCyberObservableExportAsk = async (args) => {
  const { format, stixCyberObservableId = null, exportType = null, maxMarkingDefinition = null, context = null } = args;
  const entity = stixCyberObservableId ? await loadEntityById(stixCyberObservableId, 'Stix-Observable') : null;
  const workList = await askJobExports(format, entity, exportType, maxMarkingDefinition, context, args);
  // Return the work list to do
  return map((w) => workToExportFile(w.work), workList);
};

export const stixCyberObservableImportPush = (user, entityType = null, entityId = null, file) => {
  return upload(user, 'import', file, entityType, entityId);
};

export const stixCyberObservableExportPush = async (user, entityId = null, file, context = null, listArgs = null) => {
  // Upload the document in minio
  await upload(user, 'export', file, 'stix-observable', entityId, context, listArgs);
  return true;
};
