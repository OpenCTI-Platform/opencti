import { assoc, assocPath, dissoc, map, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  listEntities,
  loadEntityByGraknId,
  loadEntityById,
  loadObservableById,
  timeSeries,
  TYPE_STIX_OBSERVABLE,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { findAll as relationFindAll } from './stixRelation';
import { elCount } from '../database/elasticSearch';
import { connectorsForEnrichment } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

export const findById = stixObservableId => {
  return loadObservableById(stixObservableId);
};
export const findAll = async args => {
  const noTypes = !args.types || args.types.length === 0;
  const finalArgs = assoc('types', noTypes ? ['Stix-Observable'] : args.types, args);
  const test = await listEntities(['name', 'description', 'observable_value'], finalArgs);
  // if (!args.firstSeenStart && !args.firstSeenStop && !args.lastSeenStart && !args.lastSeenStop) {
  //
  // }
  const compare = await relationFindAll({
    relationType: 'indicates',
    fromTypes: args.types ? args.types : ['Stix-Observable'],
    firstSeenStart: args.firstSeenStart,
    firstSeenStop: args.firstSeenStop,
    lastSeenStart: args.lastSeenStart,
    lastSeenStop: args.lastSeenStop
  }).then(async relations => {
    const observablesEdges = await Promise.all(
      map(
        n =>
          loadEntityByGraknId(n.node.toId).then(node => ({
            node: pipe(
              assoc('first_seen', n.node.first_seen),
              assoc('last_seen', n.node.last_seen)
            )(node),
            relation: n.relation,
            cursor: n.cursor
          })),
        relations.edges
      )
    );
    // const observablesEdges = pipe(
    //   map(n => assocPath(['node', 'from', 'first_seen'], n.node.first_seen, n)),
    //   map(n => assocPath(['node', 'from', 'last_seen'], n.node.last_seen, n)),
    //   map(n => ({ node: n.node.from, cursor: n.cursor }))
    // )(relations.edges);
    return assoc('edges', observablesEdges, relations);
  });
  return test;
};

// region by elastic
// TODO ONLY ES?
export const stixObservablesNumber = args => ({
  count: elCount('stix_observables', args),
  total: elCount('stix_observables', dissoc('endDate', args))
});
// endregion

// region time series
export const reportsTimeSeries = (stixObservableId, args) => {
  return timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs;
    $so has internal_id_key "${escapeString(stixObservableId)}"`,
    args
  );
};
export const stixObservablesTimeSeries = args => {
  return timeSeries(`match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'}`, args);
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
  const created = await createEntity(observableToCreate, innerType, TYPE_STIX_OBSERVABLE, 'indicator');
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
    const stixObservable = await loadObservableById(stixObservableId);
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
export const stixObservableDeleteRelation = (user, stixObservableId, relationId) => {
  return deleteRelationById(stixObservableId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData, user);
    return relationData;
  });
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
