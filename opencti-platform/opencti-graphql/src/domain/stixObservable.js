import { assoc, dissoc, map, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escape,
  executeWrite,
  listEntities,
  loadEntityById,
  timeSeriesEntities,
  TYPE_STIX_OBSERVABLE,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elCount } from '../database/elasticSearch';
import { connectorsForEnrichment } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

export const findById = stixObservableId => {
  return loadEntityById(stixObservableId);
};
export const findAll = async args => {
  const noTypes = !args.types || args.types.length === 0;
  const finalArgs = pipe(
    assoc('types', noTypes ? ['Stix-Observable'] : args.types),
    assoc('parentType', 'Stix-Observable')
  )(args);
  return listEntities(['name', 'description', 'observable_value'], finalArgs);
};

// region by elastic
export const stixObservablesNumber = args => ({
  count: elCount('stix_observables', args),
  total: elCount('stix_observables', dissoc('endDate', args))
});
// endregion

// region time series
export const reportsTimeSeries = (stixObservableId, args) => {
  const filters = [
    { isRelation: true, from: 'knowledge_aggregation', to: 'so', type: 'object_refs', value: stixObservableId }
  ];
  return timeSeriesEntities('Report', filters, args);
};
export const stixObservablesTimeSeries = args => {
  return timeSeriesEntities(args.type ? escape(args.type) : 'Stix-Observable', [], args);
};
// endregion

// region mutations
const askEnrich = async (observableId, scope) => {
  const targetConnectors = await connectorsForEnrichment(scope, true);
  // Create job for
  const workList = await Promise.all(
    map(
      connector =>
        createWork(connector, observableId).then(({ job, work }) => ({
          connector,
          job,
          work
        })),
      targetConnectors
    )
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map(data => {
      const { connector, work, job } = data;
      const message = {
        work_id: work.internal_id_key,
        job_id: job.internal_id_key,
        entity_id: observableId
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
export const stixObservableAskEnrichment = async (id, connectorId) => {
  const connector = await loadEntityById(connectorId);
  const { job, work } = await createWork(connector, id);
  const message = {
    work_id: work.internal_id_key,
    job_id: job.internal_id_key,
    entity_id: id
  };
  await pushToConnector(connector, message);
  return work;
};
export const addStixObservable = async (user, stixObservable) => {
  const innerType = stixObservable.type;
  const observableToCreate = dissoc('type', stixObservable);
  const created = await createEntity(observableToCreate, innerType, {
    modelType: TYPE_STIX_OBSERVABLE,
    stixIdType: 'observable'
  });
  await askEnrich(created.id, innerType);
  return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
};
export const stixObservableDelete = async stixObservableId => {
  return deleteEntityById(stixObservableId);
};
export const stixObservableAddRelation = (user, stixObservableId, input) => {
  return createRelation(stixObservableId, input).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixObservableEditField = (user, stixObservableId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(stixObservableId, input, wTx);
  }).then(async () => {
    const stixObservable = await loadEntityById(stixObservableId);
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
export const stixObservableDeleteRelation = async (user, stixObservableId, relationId) => {
  await deleteRelationById(relationId);
  const data = await loadEntityById(stixObservableId);
  return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixObservableCleanContext = (user, stixObservableId) => {
  delEditContext(user, stixObservableId);
  return loadEntityById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return loadEntityById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};
// endregion
