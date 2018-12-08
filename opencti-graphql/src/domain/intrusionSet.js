import { assoc, head } from 'ramda';
import { delEditContext, pubsub, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInput,
  loadByID,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Intrusion-Set', args);

export const markingDefinitions = (intrusionSetId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$intrusionSet) isa object_marking_refs; 
    $intrusionSet id ${intrusionSetId}`,
    args
  );

export const findById = intrusionSetId => loadByID(intrusionSetId);

export const addIntrusionSet = async (user, intrusionSet) => {
  const createIntrusionSet = qk(`insert $intrusionSet isa Intrusion-Set 
    has type "intrusion-set";
    $intrusionSet has name "${intrusionSet.name}";
    $intrusionSet has description "${intrusionSet.description}";
    $intrusionSet has created ${now()};
    $intrusionSet has modified ${now()};
    $intrusionSet has revoked false;
  `);
  return createIntrusionSet.then(result => {
    const { data } = result;
    return findById(head(data).intrusionSet.id).then(intrusionSetCreated => {
      pubsub.publish(BUS_TOPICS.IntrusionSet.ADDED_TOPIC, {
        intrusionSetCreated
      });
      return intrusionSetCreated;
    });
  });
};

export const intrusionSetDelete = intrusionSetId => deleteByID(intrusionSetId);

export const intrusionSetDeleteRelation = relationId => deleteByID(relationId);

export const intrusionSetAddRelation = (intrusionSetId, input) =>
  createRelation(intrusionSetId, input, BUS_TOPICS.IntrusionSet.EDIT_TOPIC);

export const intrusionSetCleanContext = (user, intrusionSetId) => {
  delEditContext(user, intrusionSetId);
  return findById(intrusionSetId).then(intrusionSet => {
    pubsub.publish(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, {
      instance: intrusionSet
    });
    return intrusionSet;
  });
};

export const intrusionSetEditContext = (user, intrusionSetId, input) => {
  setEditContext(user, intrusionSetId, input);
  findById(intrusionSetId).then(intrusionSet => {
    pubsub.publish(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, {
      instance: intrusionSet
    });
    return intrusionSet;
  });
};

export const intrusionSetEditField = (intrusionSetId, input) =>
  editInput(assoc('id', intrusionSetId, input)).then(intrusionSet => {
    pubsub.publish(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, {
      instance: intrusionSet
    });
    return intrusionSet;
  });
