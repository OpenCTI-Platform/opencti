import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  takeWriteTx,
  deleteEntityById,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareDate,
  notify,
  now,
  paginate,
  prepareString
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

export const findById = intrusionSetId => getById(intrusionSetId);

export const addIntrusionSet = async (user, intrusionSet) => {
  const wTx = await takeWriteTx();
  const intrusionSetIterator = await wTx.query(`insert $intrusionSet isa Intrusion-Set 
    has type "intrusion-set";
    $intrusionSet has stix_id "intrusion-set--${uuid()}";
    $intrusionSet has stix_label "";
    $intrusionSet has alias "";
    $intrusionSet has name "${prepareString(intrusionSet.name)}";
    $intrusionSet has description "${prepareString(intrusionSet.description)}";
    $intrusionSet has first_seen ${prepareDate(intrusionSet.first_seen)};
    $intrusionSet has first_seen_day "${dayFormat(intrusionSet.first_seen)}";
    $intrusionSet has first_seen_month "${monthFormat(
      intrusionSet.first_seen
    )}";
    $intrusionSet has first_seen_year "${yearFormat(intrusionSet.first_seen)}";
    $intrusionSet has last_seen ${prepareDate(intrusionSet.last_seen)};
    $intrusionSet has last_seen_day "${dayFormat(intrusionSet.last_seen)}";
    $intrusionSet has last_seen_month "${monthFormat(intrusionSet.last_seen)}";
    $intrusionSet has last_seen_year "${yearFormat(intrusionSet.last_seen)}";
    $intrusionSet has created ${now()};
    $intrusionSet has modified ${now()};
    $intrusionSet has revoked false;
    $intrusionSet has created_at ${now()};
    $intrusionSet has created_at_day "${dayFormat(now())}";
    $intrusionSet has created_at_month "${monthFormat(now())}";
    $intrusionSet has created_at_year "${yearFormat(now())}";       
    $intrusionSet has updated_at ${now()};
  `);
  const createIntrusionSet = await intrusionSetIterator.next();
  const createIntrusionSetId = await createIntrusionSet
    .map()
    .get('intrusionSet').id;

  if (intrusionSet.createdByRef) {
    await wTx.query(`match $from id ${createIntrusionSetId};
         $to id ${intrusionSet.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (intrusionSet.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createIntrusionSetId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      intrusionSet.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createIntrusionSetId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const intrusionSetDelete = intrusionSetId => deleteEntityById(intrusionSetId);
