import { head } from 'ramda';
import { delEditContext, pubsub, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa ThreatActor', args);

export const markingDefinitions = (threatActorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$threatActor) isa object_marking_refs; 
    $threatActor id ${threatActorId}`,
    args
  );

export const findById = threatActorId => loadByID(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const createThreatActor = qk(`insert $threatActor isa ThreatActor 
    has type "threatActor";
    $threatActor has name "${threatActor.name}";
    $threatActor has description "${threatActor.description}";
    $threatActor has created ${now()};
    $threatActor has modified ${now()};
    $threatActor has revoked false;
  `);
  return createThreatActor.then(result => {
    const { data } = result;
    return findById(head(data).threatActor.id).then(threatActorCreated => {
      pubsub.publish(BUS_TOPICS.ThreatActor.ADDED_TOPIC, {
        threatActorCreated
      });
      return threatActorCreated;
    });
  });
};

export const threatActorDelete = threatActorId => deleteByID(threatActorId);

export const threatActorDeleteRelation = relationId => deleteByID(relationId);

export const threatActorAddRelation = (threatActorId, input) =>
  createRelation(threatActorId, input, BUS_TOPICS.ThreatActor.EDIT_TOPIC);

export const threatActorCleanContext = (user, threatActorId) => {
  delEditContext(user, threatActorId);
  return findById(threatActorId).then(threatActor => {
    pubsub.publish(BUS_TOPICS.ThreatActor.EDIT_TOPIC, {
      instance: threatActor
    });
    return threatActor;
  });
};

export const threatActorEditContext = (user, threatActorId, input) => {
  setEditContext(user, threatActorId, input);
  findById(threatActorId).then(threatActor => {
    pubsub.publish(BUS_TOPICS.ThreatActor.EDIT_TOPIC, {
      instance: threatActor
    });
    return threatActor;
  });
};

export const threatActorEditField = (threatActorId, input) =>
  editInputTx(threatActorId, input).then(threatActor => {
    pubsub.publish(BUS_TOPICS.ThreatActor.EDIT_TOPIC, {
      instance: threatActor
    });
    return threatActor;
  });
