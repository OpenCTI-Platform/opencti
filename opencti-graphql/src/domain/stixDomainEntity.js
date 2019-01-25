import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  loadByName,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

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
    has name_lowercase $name
    has description_lowercase $desc;
    { $name contains "${args.search.toLowerCase()}"; } or
    { $desc contains "${args.search.toLowerCase()}"; }`,
    args,
    false
  );

export const markingDefinitions = (stixDomainEntityId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixDomainEntity) isa object_marking_refs; 
    $stixDomainEntity id ${stixDomainEntityId}`,
    args
  );

export const addStixDomainEntity = async (user, stixDomainEntity) => {
  const createStixDomainEntity = qk(`insert $stixDomainEntity isa ${
    stixDomainEntity.type
  } 
    has type "${stixDomainEntity.type.toLowerCase()}";
    $stixDomainEntity has stix_id "${stixDomainEntity.type.toLowerCase()}--${uuid()}";
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
