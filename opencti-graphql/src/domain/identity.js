import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Identity', args);

export const findById = identityId => loadByID(identityId);

export const search = args =>
  paginate(
    `match $m isa Identity
    has name $name
    has description $desc;
    { $name contains "${args.search}"; } or
    { $desc contains "${args.search}"; }`,
    args
  );

export const markingDefinitions = (identityId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$identity) isa object_marking_refs; 
    $identity id ${identityId}`,
    args
  );

export const addIdentity = async (user, identity) => {
  const createIdentity = qk(`insert $identity isa ${identity.type} 
    has type "${identity.type.toLowerCase()}";
    $identity has stix_id "${identity.type.toLowerCase()}--${uuid()}";
    $identity has name "${identity.name}";
    $identity has description "${identity.description}";
    $identity has created ${now()};
    $identity has modified ${now()};
    $identity has revoked false;
    $identity has created_at ${now()};
    $identity has updated_at ${now()};
  `);
  return createIdentity.then(result => {
    const { data } = result;
    return loadByID(head(data).identity.id).then(created =>
      notify(BUS_TOPICS.Identity.ADDED_TOPIC, created, user)
    );
  });
};

export const identityDelete = identityId => deleteByID(identityId);

export const identityAddRelation = (user, identityId, input) =>
  createRelation(identityId, input).then(relationData => {
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const identityDeleteRelation = (user, identityId, relationId) =>
  deleteRelation(identityId, relationId).then(relationData => {
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const identityCleanContext = (user, identityId) => {
  delEditContext(user, identityId);
  return loadByID(identityId).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
};

export const identityEditContext = (user, identityId, input) => {
  setEditContext(user, identityId, input);
  return loadByID(identityId).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
};

export const identityEditField = (user, identityId, input) =>
  editInputTx(identityId, input).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
