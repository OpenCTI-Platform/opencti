import { assoc, head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  qk,
  timeSeries,
  qkObjUnique,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {
  findAll as relationFindAll,
  findByType as relationFindByType,
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

export const findById = stixObservableId => loadByID(stixObservableId);

export const findByValue = args =>
  paginate(
    `match $m isa ${
      args.type ? args.type : 'Stix-Observable'
    }; $m has value_lowercase "${prepareString(args.value.toLowerCase())}"`,
    args,
    false
  );

export const search = args =>
  paginate(
    `match $m isa ${args.type ? args.type : 'Stix-Observable'}
    has value_lowercase $value;
    $m has alias_lowercase $alias;
    { $name contains "${prepareString(args.search.toLowerCase())}"; } or
    { $alias contains "${prepareString(args.search.toLowerCase())}"; }`,
    args,
    false
  );

export const createdByRef = stixObservableId =>
  qkObjUnique(
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
  if (finalArgs.relationType && finalArgs.relationType.length > 0) {
    return relationFindByType(finalArgs);
  }
  return relationFindAll(finalArgs);
};

export const addStixObservable = async (user, stixObservable) => {
  const createStixObservable = qk(`insert $stixObservable isa ${
    stixObservable.type
  } 
    has type "${prepareString(stixObservable.type.toLowerCase())}";
    $stixObservable has value "${prepareString(stixObservable.value)}";
    $stixObservable has value_lowercase "${prepareString(
      stixObservable.value.toLowerCase()
    )}";
    $stixObservable has created_at ${now()};
    $stixObservable has created_at_day "${dayFormat(now())}";
    $stixObservable has created_at_month "${monthFormat(now())}";
    $stixObservable has created_at_year "${yearFormat(now())}";      
    $stixObservable has updated_at ${now()};
  `);
  return createStixObservable.then(result => {
    const { data } = result;
    return loadByID(head(data).stixObservable.id).then(created =>
      notify(BUS_TOPICS.stixObservable.ADDED_TOPIC, created, user)
    );
  });
};

export const stixObservableDelete = stixObservableId =>
  deleteByID(stixObservableId);

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
  deleteRelation(stixObservableId, relationId).then(relationData => {
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixObservableCleanContext = (user, stixObservableId) => {
  delEditContext(user, stixObservableId);
  return loadByID(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditContext = (user, stixObservableId, input) => {
  setEditContext(user, stixObservableId, input);
  return loadByID(stixObservableId).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
};

export const stixObservableEditField = (user, stixObservableId, input) =>
  editInputTx(stixObservableId, input).then(stixObservable =>
    notify(BUS_TOPICS.stixObservable.EDIT_TOPIC, stixObservable, user)
  );
