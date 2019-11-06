import { assoc, assocPath, dissoc, map, pipe } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  graknNow,
  monthFormat,
  notify,
  loadEntityById,
  timeSeries,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { findAll as relationFindAll } from './stixRelation';
import {
  elCount,
  INDEX_STIX_OBSERVABLE,
  elLoadById,
  elLoadByStixId,
  elLoadByTerms,
  elPaginate as elPaginate
} from '../database/elasticSearch';
import { connectorsForEnrichment } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => {
  if (
    !args.firstSeenStart &&
    !args.firstSeenStop &&
    !args.lastSeenStart &&
    !args.lastSeenStop
  ) {
    return elPaginate('stix_observables', args);
  }
  return relationFindAll({
    relationType: 'indicates',
    fromTypes: args.types ? args.types : ['Stix-Observable'],
    firstSeenStart: args.firstSeenStart,
    firstSeenStop: args.firstSeenStop,
    lastSeenStart: args.lastSeenStart,
    lastSeenStop: args.lastSeenStop
  }).then(relations => {
    const observablesEdges = pipe(
      map(n => assocPath(['node', 'from', 'first_seen'], n.node.first_seen, n)),
      map(n => assocPath(['node', 'from', 'last_seen'], n.node.last_seen, n)),
      map(n => ({ node: n.node.from, cursor: n.cursor }))
    )(relations.edges);
    return assoc('edges', observablesEdges, relations);
  });
};

export const stixObservablesNumber = args => ({
  count: elCount('stix_observables', args),
  total: elCount('stix_observables', dissoc('endDate', args))
});

export const stixObservablesTimeSeries = args => {
  return timeSeries(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'}`,
    args
  );
};

export const findById = stixObservableId => {
  return elLoadById(stixObservableId, [INDEX_STIX_OBSERVABLE]);
};

export const findByStixId = args => {
  return elLoadByStixId(args.stix_id, [INDEX_STIX_OBSERVABLE]);
};

export const findByValue = args =>
  elLoadByTerms(
    [{ 'observable_value.keyword': args.observableValue }],
    [INDEX_STIX_OBSERVABLE]
  );

export const search = args => elPaginate('stix_observables', args);

export const reportsTimeSeries = (stixObservableId, args) => {
  return timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs;
    $so has internal_id_key "${escapeString(stixObservableId)}"`,
    args
  );
};

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
  const observableId = await executeWrite(async wTx => {
    const stixId = stixObservable.stix_id_key;
    const observableValue = stixObservable.observable_value;
    const internalId = stixObservable.internal_id_key
      ? escapeString(stixObservable.internal_id_key)
      : uuid();
    const query = `insert $stixObservable isa ${escape(stixObservable.type)},
    has internal_id_key "${internalId}",
    has stix_id_key "${stixId ? escapeString(stixId) : `indicator--${uuid()}`}",
    has entity_type "${escapeString(stixObservable.type.toLowerCase())}",
    has name "",
    has description "${escapeString(stixObservable.description)}",
    has observable_value "${escapeString(observableValue)}",
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",      
    has updated_at ${graknNow()};
  `;
    logger.debug(`[GRAKN - infer: false] addStixObservable > ${query}`);
    const stixObservableIterator = await wTx.tx.query(query);
    const createStixObservable = await stixObservableIterator.next();
    const createdId = await createStixObservable.map().get('stixObservable').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdId, stixObservable.createdByRef);
    await linkMarkingDef(wTx, createdId, stixObservable.markingDefinitions);
    return internalId;
  });
  return loadEntityById(observableId).then(async created => {
    // Enqueue enrich job
    await askEnrich(observableId, stixObservable.type);
    return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
  });
};

export const stixObservableDelete = async stixObservableId => {
  return deleteEntityById(stixObservableId);
};

export const stixObservableAddRelation = (user, stixObservableId, input) => {
  return createRelation(stixObservableId, input).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};

export const stixObservableDeleteRelation = (
  user,
  stixObservableId,
  relationId
) => {
  return deleteRelationById(stixObservableId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};

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

export const stixObservableEditField = (user, stixObservableId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(stixObservableId, input, wTx);
  }).then(async () => {
    const stixObservable = await elLoadById(stixObservableId);
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
