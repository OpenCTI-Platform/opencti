import { head, map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelationByID,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args =>
  paginate('match $m isa External-Reference', args);
export const findAllBySo = args =>
  paginate(
    `match $externalReference isa External-Reference; 
    $rel(external_reference:$externalReference, so:$so) isa external_references; 
    $so id ${args.objectId}`,
    args
  );

export const findById = externalReferenceId => loadByID(externalReferenceId);

export const search = args =>
  paginate(
    `match $m isa External-Reference 
    has source_name $sn
    has description $desc
    has url $url;
    { $sn contains "${args.search}"; } or
    { $desc contains "${args.search}"; } or
    { $url contains "${args.search}"; }`,
    args
  );

export const addExternalReference = async (user, externalReference) => {
  const createExternalReference = qk(`insert $externalReference isa External-Reference 
    has type "external-reference";
    $externalReference has stix_id "external-reference--${uuid()}";
    $externalReference has source_name "${externalReference.source_name}";
    $externalReference has description "${externalReference.description}";
    $externalReference has url "${externalReference.url}";
    $externalReference has hash "${externalReference.hash}";
    $externalReference has external_id "${externalReference.external_id}";
    $externalReference has created ${now()};
    $externalReference has modified ${now()};
    $externalReference has revoked false;
    $externalReference has created_at ${now()};
    $externalReference has updated_at ${now()};
  `);
  return createExternalReference.then(result => {
    const { data } = result;
    return loadByID(head(data).externalReference.id).then(created =>
      notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created)
    );
  });
};

export const externalReferenceDelete = externalReferenceId =>
  deleteByID(externalReferenceId);

export const externalReferenceDeleteRelation = (
  user,
  externalReferenceId,
  relationId
) =>
  deleteRelationByID(relationId).then(() => {
    loadByID(externalReferenceId).then(externalReferenceData => {
      notify(BUS_TOPICS.Group.EDIT_TOPIC, externalReferenceData, user);
    });
    return relationId;
  });

export const externalReferenceAddRelation = (
  user,
  externalReferenceId,
  input
) =>
  createRelation(externalReferenceId, input).then(relationData => {
    notify(BUS_TOPICS.Group.EDIT_TOPIC, relationData.from, user);
    return relationData;
  });

export const externalReferenceCleanContext = (user, externalReferenceId) => {
  delEditContext(user, externalReferenceId);
  return loadByID(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = (
  user,
  externalReferenceId,
  input
) => {
  setEditContext(user, externalReferenceId, input);
  loadByID(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditField = (user, externalReferenceId, input) =>
  editInputTx(externalReferenceId, input).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
