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
  orderBy = 'definition',
  orderMode = 'asc'
) => loadAll('Marking-Definition', first, after, orderBy, orderMode);

export const findById = markingDefinitionId => loadByID(markingDefinitionId);

export const addMarkingDefinition = async (user, markingDefinition) => {
  const createMarkingDefinition = qk(`insert $markingDefinition isa Marking-Definition 
    has type "Marking-Definition";
    $markingDefinition has definition_type "${
      markingDefinition.definition_type
    }";
    $markingDefinition has definition "${markingDefinition.definition}";
    $markingDefinition has created ${now()};
    $markingDefinition has modified ${now()};
  `);
  return createMarkingDefinition.then(result => {
    const { data } = result;
    return findById(head(data).markingDefinition.id).then(
      markingDefinitionCreated => {
        pubsub.publish(BUS_TOPICS.MarkingDefinition.ADDED_TOPIC, {
          markingDefinitionCreated
        });
        return {
          markingDefinitionEdge: {
            node: markingDefinitionCreated
          }
        };
      }
    );
  });
};

export const deleteMarkingDefinition = markingDefinitionId =>
  deleteByID(markingDefinitionId);

export const markingDefinitionEditContext = (user, input) => {
  const { focusOn, isTyping } = input;
  // Context map of markingDefinition users notifications
  // SET edit:{V15431} '[ {"user": "email01", "focusOn": "name", "isTyping": true } ]'
  return [
    {
      username: user.email,
      focusOn,
      isTyping
    }
  ];
};

export const markingDefinitionEditField = (user, input) =>
  editInput(input, BUS_TOPICS.MarkingDefinition.EDIT_TOPIC).then(
    markingDefinition => ({
      markingDefinitionEdge: {
        node: markingDefinition
      }
    })
  );
