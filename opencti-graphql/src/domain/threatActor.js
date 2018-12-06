import { head } from 'ramda';
import { pubsub } from '../database/redis';
import {
  deleteByID,
  loadByID,
  qk,
  now,
  editInput,
  paginate
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Threat-Actor', args);

export const findMarkingDef = (threatActorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$threatActor) isa object_marking_refs; 
    $threatActor id ${threatActorId}`,
    args
  );

export const findById = threatActorId => loadByID(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const createThreatActor = qk(`insert $threatActor isa Threat-Actor 
    has type "Threat-Actor";
    $threatActor has name "${threatActor.name}";
    $threatActor has description "${threatActor.description}";
    $threatActor has created ${now()};
    $threatActor has modified ${now()};
    $threatActor has revoked false;
  `);
  return createThreatActor.then(result => {
    const { data } = result;
    return findById(head(data).threatActor.id).then(threatActorCreated => {
      pubsub.publish(BUS_TOPICS.ThreatActor.ADDED_TOPIC, { threatActorCreated });
      return threatActorCreated;
    });
  });
};

export const deleteThreatActor = threatActorId => deleteByID(threatActorId);

export const threatActorEditContext = (user, input) => {
  const { focusOn, isTyping } = input;
  // Context map of threatActor users notifications
  // SET edit:{V15431} '[ {"user": "email01", "focusOn": "name", "isTyping": true } ]'
  return [
    {
      username: user.email,
      focusOn,
      isTyping
    }
  ];
};

export const threatActorEditField = (user, input) =>
  editInput(input, BUS_TOPICS.ThreatActor.EDIT_TOPIC);
