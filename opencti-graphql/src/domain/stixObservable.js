import { assoc, map, head, join } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
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
  prepareString
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';
import { index } from '../database/elasticSearch';

export const findAll = args =>
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

export const stixObservablesTimeSeries = args =>
  timeSeries(`match $x isa ${args.type ? args.type : 'Stix-Observable'}`, args);

export const findById = stixObservableId => getById(stixObservableId);

export const findByValue = args =>
  paginate(
    `match $x isa ${args.type ? args.type : 'Stix-Observable'};
    $x has observable_value "${prepareString(args.observable_value)}"`,
    args,
    false
  );

export const search = args =>
  paginate(
    `match $x isa ${args.type ? args.type : 'Stix-Observable'};
    $x has observable_value $value;
    $x has name $name;
    { $value contains "${prepareString(args.search)}"; } or
    { $name contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const createdByRef = stixObservableId =>
  getObject(
    `match $i isa Identity;
    $rel(creator:$i, so:$x) isa created_by_ref; 
    $x id ${stixObservableId}; 
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
    $x id ${stixObservableId}`,
    args,
    false
  );

export const reports = (stixObservableId, args) =>
  paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$x) isa object_refs; 
    $x id ${stixObservableId}`,
    args
  );

export const reportsTimeSeries = (stixObservableId, args) =>
  timeSeries(
    `match $x isa Report; 
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs;
    $so id ${stixObservableId}`,
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
  const query = `insert $stixObservable isa ${stixObservable.type},
    has entity_type "${prepareString(stixObservable.type.toLowerCase())}",
    has name "",
    has description "",
    has observable_value "${prepareString(stixObservable.observable_value)}",
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",      
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const stixObservableIterator = await wTx.query(query);
  const createStixObservable = await stixObservableIterator.next();
  const createdStixObservableId = await createStixObservable
    .map()
    .get('stixObservable').id;

  if (stixObservable.createdByRef) {
    await wTx.query(
      `match $from id ${createdStixObservableId};
      $to id ${stixObservable.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (stixObservable.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdStixObservableId}; 
        $to id ${markingDefinition}; 
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixObservable.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdStixObservableId).then(created => {
    index('stix-observable', 'stix_observable', created);
    return notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user)
  });
};

export const stixObservableDelete = stixObservableId =>
  deleteEntityById(stixObservableId);

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
  updateAttribute(stixObservableId, input).then(stixObservable =>
    notify(BUS_TOPICS.StixObservable.EDIT_TOPIC, stixObservable, user)
  );
