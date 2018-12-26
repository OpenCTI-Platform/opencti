import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
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

export const markingDefinitions = (identityId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$identity) isa object_marking_refs; 
    $identity id ${identityId}`,
    args
  );

export const addIdentity = async (user, identity) => {
  const createIdentity = qk(`insert $identity isa Identity 
    has type "identity";
    $identity has stix_id "identity--${uuid()}";
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

export const identityDeleteRelation = relationId => deleteByID(relationId);

export const identityAddRelation = (user, identityId, input) =>
  createRelation(identityId, input).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );

export const identityCleanContext = (user, identityId) => {
  delEditContext(user, identityId);
  return loadByID(identityId).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
};

export const identityEditContext = (user, identityId, input) => {
  setEditContext(user, identityId, input);
  loadByID(identityId).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
};

export const identityEditField = (user, identityId, input) =>
  editInputTx(identityId, input).then(identity =>
    notify(BUS_TOPICS.Identity.EDIT_TOPIC, identity, user)
  );
