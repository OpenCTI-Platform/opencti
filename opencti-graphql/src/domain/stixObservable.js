import { assoc, map, pipe, assocPath } from 'ramda';
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
  now,
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
  deleteEntity,
  index,
  paginate as elPaginate
} from '../database/elasticSearch';

export const findAll = args => {
  if (
    !args.firstSeenStart &&
    !args.firstSeenStop &&
    !args.lastSeenStart &&
    !args.lastSeenStop
  ) {
    return elPaginate('stix-observables', args);
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
/*
  paginate(
    `match ${
      args.types
        ? `${join(
            ' ',
            map(type => `{ $x isa ${type}; } or`, args.types)
          )} { $x isa ${head(args.types)}; }`
        : '$x isa Stix-Observable'
    }`,
    args,
    false
  );
*/

export const stixObservablesTimeSeries = args =>
  timeSeries(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'}`,
    args
  );

export const findById = stixObservableId => getById(stixObservableId);

export const findByValue = args =>
  paginate(
    `match $x isa ${args.type ? escape(args.type) : 'Stix-Observable'};
    $x has observable_value "${escapeString(args.observableValue)}"`,
    args,
    false
  );

export const search = args => elPaginate('stix-observables', args);
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

export const createdByRef = stixObservableId =>
  getObject(
    `match $i isa Identity;
    $rel(creator:$i, so:$x) isa created_by_ref; 
    $x has internal_id "${escapeString(stixObservableId)}"; 
    get $i, $rel; 
    offset 0; 
    limit 1;`,
    'i',
    'rel'
  );

export const markingDefinitions = (stixObservableId, args) =>
  paginate(
    `match $m isa Marking-Definition;
    $rel(marking:$m, so:$x) isa object_marking_refs; 
    $x has internal_id "${escapeString(stixObservableId)}"`,
    args,
    false
  );

export const reports = (stixObservableId, args) =>
  paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x has internal_id "${escapeString(stixObservableId)}"`,
    args
  );

export const reportsTimeSeries = (stixObservableId, args) =>
  timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs;
    $so has internal_id "${escapeString(stixObservableId)}"`,
    args
  );

export const stixRelations = (stixObservableId, args) => {
  const finalArgs = assoc('fromId', stixObservableId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  return relationFindAll(finalArgs);
};

export const addStixObservable = async (user, stixObservable) => {
  const wTx = await takeWriteTx();
  const internalId = stixObservable.internal_id
    ? escapeString(stixObservable.internal_id)
    : uuid();
  const query = `insert $stixObservable isa ${escape(stixObservable.type)},
    has internal_id "${internalId}",
    has stix_id "${
      stixObservable.stix_id
        ? escapeString(stixObservable.stix_id)
        : `observable--${uuid()}`
    }",
    has entity_type "${escapeString(stixObservable.type.toLowerCase())}",
    has name "",
    has description "",
    has observable_value "${escapeString(stixObservable.observable_value)}",
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",      
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
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

  return getById(internalId).then(created => {
    index('stix-observables', 'stix_observable', created);
    return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user);
  });
};

export const stixObservableDelete = async stixObservableId => {
  const graknId = await getId(stixObservableId);
  await deleteEntity('stix-observables', 'stix_observable', graknId);
  return deleteEntityById(stixObservableId);
};

export const stixObservableAddRelation = (user, stixObservableId, input) =>
  createRelation(stixObservableId, input).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixObservableDeleteRelation = (
  user,
  stixObservableId,
  relationId
) =>
  deleteRelationById(stixObservableId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

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

export const stixObservableEditField = (user, stixObservableId, input) =>
  updateAttribute(stixObservableId, input).then(stixObservable => {
    index('stix-observables', 'stix_observable', stixObservable);
    return notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user);
  });
