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

export const addExternalReference = async (user, externalReference) => {
  const createExternalReference = qk(`insert $externalReference isa External-Reference 
    has type "marking-definition";
    $externalReference has stix_id "marking-definition--${uuid()}";
    $externalReference has definition_type "${
      externalReference.definition_type
    }";
    $externalReference has definition "${externalReference.definition}";
    $externalReference has color "${externalReference.color}";
    $externalReference has level ${externalReference.level};
    $externalReference has created ${now()};
    $externalReference has modified ${now()};
    $externalReference has revoked false;
    $externalReference has created_at ${now()};
    $externalReference has updated_at ${now()};
  `);
  return createExternalReference.then(result => {
    const { data } = result;
    return findById(head(data).externalReference.id).then(created =>
      notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created)
    );
  });
};

export const addExternalReferencesTo = (objectId, externalReferencesIds) => {

}

export const externalReferenceDelete = externalReferenceId =>
  deleteByID(externalReferenceId);

export const externalReferenceDeleteRelation = relationId =>
  deleteByID(relationId);

export const externalReferenceAddRelation = (externalReferenceId, input) =>
  createRelation(externalReferenceId, input).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference)
  );

export const externalReferenceCleanContext = (user, externalReferenceId) => {
  delEditContext(user, externalReferenceId);
  return findById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference)
  );
};

export const externalReferenceEditContext = (
  user,
  externalReferenceId,
  input
) => {
  setEditContext(user, externalReferenceId, input);
  findById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference)
  );
};

export const externalReferenceEditField = (externalReferenceId, input) =>
  editInputTx(externalReferenceId, input).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference)
  );
