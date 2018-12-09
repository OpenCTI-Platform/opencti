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
    $intrusionSet has stix_id "intrusion-set--${uuid()}";
    $intrusionSet has name "${intrusionSet.name}";
    $intrusionSet has description "${intrusionSet.description}";
    $intrusionSet has created ${now()};
    $intrusionSet has modified ${now()};
    $intrusionSet has revoked false;
    $intrusionSet has created_at ${now()};
    $intrusionSet has updated_at ${now()};
  `);
  return createIntrusionSet.then(result => {
    const { data } = result;
    return findById(head(data).intrusionSet.id).then(created =>
      notify(BUS_TOPICS.IntrusionSet.ADDED_TOPIC, created)
    );
  });
};

export const intrusionSetDelete = intrusionSetId => deleteByID(intrusionSetId);

export const intrusionSetDeleteRelation = relationId => deleteByID(relationId);

export const intrusionSetAddRelation = (intrusionSetId, input) =>
  createRelation(intrusionSetId, input).then(intrusionSet =>
    notify(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, intrusionSet)
  );

export const intrusionSetCleanContext = (user, intrusionSetId) => {
  delEditContext(user, intrusionSetId);
  return findById(intrusionSetId).then(intrusionSet =>
    notify(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, intrusionSet)
  );
};

export const intrusionSetEditContext = (user, intrusionSetId, input) => {
  setEditContext(user, intrusionSetId, input);
  findById(intrusionSetId).then(intrusionSet =>
    notify(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, intrusionSet)
  );
};

export const intrusionSetEditField = (intrusionSetId, input) =>
  editInputTx(intrusionSetId, input).then(intrusionSet =>
    notify(BUS_TOPICS.IntrusionSet.EDIT_TOPIC, intrusionSet)
  );
