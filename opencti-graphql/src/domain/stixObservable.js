import { assoc, map } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteEntityById,
  deleteRelationById,
  editInputTx,
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
import { BUS_TOPICS } from '../config/conf';
import {
  findAll as relationFindAll,
  search as relationSearch
} from './stixRelation';

export const findAll = args =>
  paginate(
    `match $m isa ${args.type ? args.type : 'Stix-Observable'}`,
    args,
    false
  );

export const stixObservablesTimeSeries = args =>
  timeSeries(`match $x isa ${args.type ? args.type : 'Stix-Observable'}`, args);

export const findById = stixObservableId => getById(stixObservableId);

export const findByValue = args =>
  paginate(
    `match $m isa ${
      args.type ? args.type : 'Stix-Observable'
    }; $m has value "${prepareString(args.value)}"`,
    args,
    false
  );

export const search = args =>
  paginate(
    `match $m isa ${args.type ? args.type : 'Stix-Observable'}
    has value $value;
    $m has alias $alias;
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const createdByRef = stixObservableId =>
  getObject(
    `match $x isa Identity; 
    $rel(creator:$x, so:$stixObservable) isa created_by_ref; 
    $stixObservable id ${stixObservableId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const markingDefinitions = (stixObservableId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixObservable) isa object_marking_refs; 
    $stixObservable id ${stixObservableId}`,
    args,
    false
  );

export const reports = (stixObservableId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixObservable) isa object_refs; 
    $stixObservable id ${stixObservableId}`,
    args
  );

export const reportsTimeSeries = (stixObservableId, args) =>
  timeSeries(
    `match $m isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixObservable) isa object_refs; 
    $stixObservable id ${stixObservableId}`,
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
  const stixObservableIterator = await wTx.query(`insert $stixObservable isa ${
    stixObservable.type
  } 
    has type "${prepareString(stixObservable.type.toLowerCase())}";
    $stixObservable has value "${prepareString(stixObservable.value)}";
    $stixObservable has created_at ${now()};
    $stixObservable has created_at_day "${dayFormat(now())}";
    $stixObservable has created_at_month "${monthFormat(now())}";
    $stixObservable has created_at_year "${yearFormat(now())}";      
    $stixObservable has updated_at ${now()};
  `);
  const createStixObservable = await stixObservableIterator.next();
  const createdStixObservableId = await createStixObservable.map().get('stixObservable').id;

  if (stixObservable.createdByRef) {
    await wTx.query(`match $from id ${createdStixObservableId};
         $to id ${stixObservable.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (stixObservable.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdStixObservableId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixObservable.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdStixObservableId).then(created =>
    notify(BUS_TOPICS.StixObservable.ADDED_TOPIC, created, user)
  );
};

export const stixObservableDelete = stixObservableId =>
  deleteEntityById(stixObservableId);

export const stixObservableAddRelation = (user, stixObservableId, input) =>
  createRelation(stixObservableId, input).then(relationData => {
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixObservableDeleteRelation = (
  user,
  stixObservableId,
  relationId
) =>
  deleteRelationById(stixObservableId, relationId).then(relationData => {
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixObservableCleanContext = (user, stixObservableId) => {
  delEditContext(user, stixObservableId);
  return getById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return getById(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditField = (user, stixObservableId, input) =>
  editInputTx(stixObservableId, input).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
