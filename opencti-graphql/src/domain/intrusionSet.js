import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  takeTx,
  deleteByID,
  loadByID,
  notify,
  now,
  paginate,
  yearFormat,
  monthFormat
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
  const wTx = await takeTx();
  const intrusionSetIterator = await wTx.query(`insert $intrusionSet isa Intrusion-Set 
    has type "intrusion-set";
    $intrusionSet has stix_id "intrusion-set--${uuid()}";
    $intrusionSet has stix_label "";
    $intrusionSet has stix_label_lowercase "";
    $intrusionSet has alias "";
    $intrusionSet has alias_lowercase "";
    $intrusionSet has name "${intrusionSet.name}";
    $intrusionSet has description "${intrusionSet.description}";
    $intrusionSet has name_lowercase "${intrusionSet.name.toLowerCase()}";
    $intrusionSet has description_lowercase "${
      intrusionSet.description ? intrusionSet.description.toLowerCase() : ''
    }";
    $intrusionSet has created ${now()};
    $intrusionSet has modified ${now()};
    $intrusionSet has revoked false;
    $intrusionSet has created_at ${now()};
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

  return loadByID(createIntrusionSetId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const intrusionSetDelete = intrusionSetId => deleteByID(intrusionSetId);
