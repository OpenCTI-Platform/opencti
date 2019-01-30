import { assoc, head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  monthFormat,
  notify,
  now,
  paginate,
  qk,
  qkObjUnique,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {
  findAll as relationFindAll,
  findByType as relationFindByType,
  search as relationSearch
} from './stixRelation';

export const findAll = args =>
  paginate('match $m isa Stix-Domain-Entity', args, false);

export const findById = stixDomainEntityId => loadByID(stixDomainEntityId);

export const findByName = args =>
  paginate(
    `match $m isa Stix-Domain-Entity; $m has name "${args.name}"`,
    args,
    false
  );

export const search = args =>
  paginate(
    `match $m isa Stix-Domain-Entity
    has name_lowercase $name;
    $m has description_lowercase $desc;
    $m has alias_lowercase $alias;
    { $name contains "${args.search.toLowerCase()}"; } or
    { $desc contains "${args.search.toLowerCase()}"; } or 
    { $alias contains "${args.search.toLowerCase()}"; }`,
    args,
    false
  );

export const createdByRef = stixDomainEntityId =>
  qkObjUnique(
    `match $x isa Identity; 
    $rel(creator:$x, so:$stixDomainEntity) isa created_by_ref; 
    $stixDomainEntity id ${stixDomainEntityId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const killChainPhases = (stixDomainEntityId, args) =>
  paginate(
    `match $kc isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$kc, phase_belonging:$stixDomainEntity) isa kill_chain_phases; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const markingDefinitions = (stixDomainEntityId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixDomainEntity) isa object_marking_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const reports = (stixDomainEntityId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixDomainEntity) isa object_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const stixRelations = (stixDomainEntityId, args) => {
  const finalArgs = assoc('fromId', stixDomainEntityId, args);
  if (finalArgs.search && finalArgs.search.length > 0) {
    return relationSearch(finalArgs);
  }
  if (finalArgs.relationType && finalArgs.relationType.length > 0) {
    return relationFindByType(finalArgs);
  }
  return relationFindAll(finalArgs);
};

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const createStixDomainEntity = qk(`insert $stixDomainEntity isa ${
    stixDomainEntity.type
  } 
    has type "${stixDomainEntity.type.toLowerCase()}";
    $stixDomainEntity has stix_id "${stixDomainEntity.type.toLowerCase()}--${uuid()}";
    $stixDomainEntity has stix_label "";
    $stixDomainEntity has stix_label_lowercase "";
    $stixDomainEntity has alias "";
    $stixDomainEntity has alias_lowercase "";
    $stixDomainEntity has name "${stixDomainEntity.name}";
    $stixDomainEntity has description "${stixDomainEntity.description}";
    $stixDomainEntity has name_lowercase "${stixDomainEntity.name.toLowerCase()}";
    $stixDomainEntity has description_lowercase "${
      stixDomainEntity.description
        ? stixDomainEntity.description.toLowerCase()
        : ''
    }";
    $stixDomainEntity has created ${now()};
    $stixDomainEntity has modified ${now()};
    $stixDomainEntity has revoked false;
    $stixDomainEntity has created_at ${now()};
    $stixDomainEntity has created_at_month "${monthFormat(now())}";
    $stixDomainEntity has created_at_year "${yearFormat(now())}";      
    $stixDomainEntity has updated_at ${now()};
  `);
  return createStixDomainEntity.then(result => {
    const { data } = result;
    return loadByID(head(data).stixDomainEntity.id).then(created =>
      notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
    );
  });
};

export const stixDomainEntityDelete = stixDomainEntityId =>
  deleteByID(stixDomainEntityId);

export const stixDomainEntityAddRelation = (user, stixDomainEntityId, input) =>
  createRelation(stixDomainEntityId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityDeleteRelation = (
  user,
  stixDomainEntityId,
  relationId
) =>
  deleteRelation(stixDomainEntityId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainEntityCleanContext = (user, stixDomainEntityId) => {
  delEditContext(user, stixDomainEntityId);
  return loadByID(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditContext = (
  user,
  stixDomainEntityId,
  input
) => {
  setEditContext(user, stixDomainEntityId, input);
  return loadByID(stixDomainEntityId).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
};

export const stixDomainEntityEditField = (user, stixDomainEntityId, input) =>
  editInputTx(stixDomainEntityId, input).then(stixDomainEntity =>
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, stixDomainEntity, user)
  );
