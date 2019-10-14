import { assoc, map, pipe, assocPath, dissoc } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escape,
  escapeString,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  updateAttribute,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  graknNow,
  paginate,
  takeWriteTx,
  timeSeries,
  getObject,
  getId,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';
import {
  countEntities,
  deleteEntity,
  paginate as elPaginate
} from '../database/elasticSearch';
import { stableUUID } from '../database/utils';
import { connectorsForEnrichment } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

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
  count: countEntities('stix_observables', args),
  total: countEntities('stix_observables', dissoc('endDate', args))
});

export const stixObservablesTimeSeries = args => {
  return timeSeries(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'}`,
    args
  );
};

export const findById = stixObservableId => getById(stixObservableId);

export const findByValue = args => {
  return paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'};
    $x has observable_value "${escapeString(args.observableValue)}"`,
    args,
    false
  );
};

export const search = args => elPaginate('stix_observables', args);
/*
  paginate(
    `match $x isa ${args.type ? args.type : 'Stix-Observable'};
    $x has observable_value $value;
    $x has name $name;
    { $value contains "${escapeString(args.search)}"; } or
    { $name contains "${escapeString(args.search)}"; }`,
    args,
    false
  );
*/

export const createdByRef = stixObservableId => {
  return getObject(
    `match $i isa Identity;
    $rel(creator:$i, so:$x) isa created_by_ref; 
    $x has internal_id "${escapeString(stixObservableId)}"; 
    get; 
    offset 0; 
    limit 1;`,
    'i',
    'rel'
  );
};

export const markingDefinitions = (stixObservableId, args) => {
  return paginate(
    `match $m isa Marking-Definition;
    $rel(marking:$m, so:$x) isa object_marking_refs; 
    $x has internal_id "${escapeString(stixObservableId)}"`,
    args,
    false,
    null,
    false,
    false
  );
};

export const reports = (stixObservableId, args) => {
  return paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x has internal_id "${escapeString(stixObservableId)}"`,
    args
  );
};

export const reportsTimeSeries = (stixObservableId, args) => {
  return timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs;
    $so has internal_id "${escapeString(stixObservableId)}"`,
    args
  );
};

export const stixRelations = (stixObservableId, args) => {
  const finalArgs = assoc('fromId', stixObservableId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};

const askEnrich = async (observableId, scope) => {
  const targetConnectors = await connectorsForEnrichment(scope, true);
  // Create job for
  const workList = await Promise.all(
    map(
      connector =>
        createWork(connector, observableId).then(work => ({ connector, work })),
      targetConnectors
    )
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map(data => {
      const { connector, work } = data;
      const message = { job_id: work.internal_id, entity_id: observableId };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};

export const stixObservableAskEnrichment = async (id, connectorId) => {
  const connector = await getById(connectorId);
  const work = await createWork(connector, id);
  const message = { job_id: work.internal_id, entity_id: id };
  await pushToConnector(connector, message);
  return work;
};

export const addStixObservable = async (user, stixObservable) => {
  const wTx = await takeWriteTx();
  const stixId = stixObservable.stix_id;
  const observableValue = stixObservable.observable_value;
  const internalId = stixObservable.internal_id
    ? escapeString(stixObservable.internal_id)
    : uuid();
  const query = `insert $stixObservable isa ${escape(stixObservable.type)},
    has internal_id "${internalId}",
    has stix_id "${
      stixId
        ? escapeString(stixId)
        : `indicator--${stableUUID(observableValue)}`
    }",
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
  const createdStixObservableId = await createStixObservable
    .map()
    .get('stixObservable').id;

  if (stixObservable.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdStixObservableId};
      $to has internal_id "${escapeString(stixObservable.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (stixObservable.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdStixObservableId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixObservable.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  // Enqueue enrich job
  await askEnrich(internalId, stixObservable.type);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
  });
};

export const stixObservableDelete = async stixObservableId => {
  const graknId = await getId(stixObservableId);
  await deleteEntity('stix_observables', graknId);
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
  return getById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return getById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditField = (user, stixObservableId, input) => {
  return updateAttribute(stixObservableId, input).then(stixObservable => {
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
};
