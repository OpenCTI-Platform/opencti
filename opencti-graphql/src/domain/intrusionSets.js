import { head } from 'ramda';
import { pubsub } from '../database/redis';
import {
  deleteByID,
  loadAll,
  loadByID,
  qk,
  now,
  editInput
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = async (
  first = 25,
  after = undefined,
  orderBy = 'name',
  orderMode = 'asc'
) => loadAll('IntrusionSet', first, after, orderBy, orderMode);

export const findMarkingDefinition = intrusionSet => {
  console.log('findMarkingDefinition', intrusionSet);
  return [];
};

export const findById = intrusionSetId => loadByID(intrusionSetId);

export const addIntrusionSet = async (user, intrusionSet) => {
  const createIntrusionSet = qk(`insert $intrusionSet isa Intrusion-Set 
    has type "Intrusion-Set";
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

export const deleteIntrusionSet = intrusionSetId => deleteByID(intrusionSetId);

export const intrusionSetEditContext = (user, input) => {
  const { focusOn, isTyping } = input;
  // Context map of intrusionSet users notifications
  // SET edit:{V15431} '[ {"user": "email01", "focusOn": "name", "isTyping": true } ]'
  return [
    {
      username: user.email,
      focusOn,
      isTyping
    }
  ];
};

export const intrusionSetEditField = (user, input) =>
  editInput(input, BUS_TOPICS.IntrusionSet.EDIT_TOPIC);
