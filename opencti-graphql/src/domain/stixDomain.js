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

export const findAll = args => paginate('match $m isa StixDomain', args);

export const findById = stixDomainId => loadByID(stixDomainId);

export const search = args =>
  paginate(
    `match $m isa Stix-Domain
    has name $name
    has description $desc;
    { $name contains "${args.search}"; } or
    { $desc contains "${args.search}"; }`,
    args
  );

export const markingDefinitions = (stixDomainId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixDomain) isa object_marking_refs; 
    $stixDomain id ${stixDomainId}`,
    args
  );

export const addStixDomain = async (user, stixDomain) => {
  const createStixDomain = qk(`insert $stixDomain isa ${stixDomain.type} 
    has type "${stixDomain.type.toLowerCase()}";
    $stixDomain has stix_id "${stixDomain.type.toLowerCase()}--${uuid()}";
    $stixDomain has name "${stixDomain.name}";
    $stixDomain has description "${stixDomain.description}";
    $stixDomain has created ${now()};
    $stixDomain has modified ${now()};
    $stixDomain has revoked false;
    $stixDomain has created_at ${now()};
    $stixDomain has updated_at ${now()};
  `);
  return createStixDomain.then(result => {
    const { data } = result;
    return loadByID(head(data).stixDomain.id).then(created =>
      notify(BUS_TOPICS.StixDomain.ADDED_TOPIC, created, user)
    );
  });
};

export const stixDomainDelete = stixDomainId => deleteByID(stixDomainId);

export const stixDomainAddRelation = (user, stixDomainId, input) =>
  createRelation(stixDomainId, input).then(relationData => {
    notify(BUS_TOPICS.StixDomain.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainDeleteRelation = (user, stixDomainId, relationId) =>
  deleteRelation(stixDomainId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixDomain.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixDomainCleanContext = (user, stixDomainId) => {
  delEditContext(user, stixDomainId);
  return loadByID(stixDomainId).then(stixDomain =>
    notify(BUS_TOPICS.StixDomain.EDIT_TOPIC, stixDomain, user)
  );
};

export const stixDomainEditContext = (user, stixDomainId, input) => {
  setEditContext(user, stixDomainId, input);
  return loadByID(stixDomainId).then(stixDomain =>
    notify(BUS_TOPICS.StixDomain.EDIT_TOPIC, stixDomain, user)
  );
};

export const stixDomainEditField = (user, stixDomainId, input) =>
  editInputTx(stixDomainId, input).then(stixDomain =>
    notify(BUS_TOPICS.StixDomain.EDIT_TOPIC, stixDomain, user)
  );
