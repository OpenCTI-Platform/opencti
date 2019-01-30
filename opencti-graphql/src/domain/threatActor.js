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

export const findAll = args => paginate('match $m isa Threat-Actor', args);

export const markingDefinitions = (threatActorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$threatActor) isa object_marking_refs; 
    $threatActor id ${threatActorId}`,
    args
  );

export const findById = threatActorId => loadByID(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const wTx = await takeTx();
  const threatActorIterator = await wTx.query(`insert $threatActor isa Threat-Actor 
    has type "threat-actor";
    $threatActor has stix_id "threat-actor--${uuid()}";
    $threatActor has stix_label "";
    $threatActor has stix_label_lowercase "";
    $threatActor has alias "";
    $threatActor has alias_lowercase "";
    $threatActor has name "${threatActor.name}";
    $threatActor has description "${threatActor.description}";
    $threatActor has name_lowercase "${threatActor.name.toLowerCase()}";
    $threatActor has description_lowercase "${
      threatActor.description ? threatActor.description.toLowerCase() : ''
    }";
    $threatActor has created ${now()};
    $threatActor has modified ${now()};
    $threatActor has revoked false;
    $threatActor has created_at ${now()};
    $threatActor has created_at_month "${monthFormat(now())}";
    $threatActor has created_at_year "${yearFormat(now())}";        
    $threatActor has updated_at ${now()};
  `);
  const createThreatActor = await threatActorIterator.next();
  const createThreatActorId = await createThreatActor.map().get('threatActor')
    .id;

  if (threatActor.createdByRef) {
    await wTx.query(`match $from id ${createThreatActorId};
         $to id ${threatActor.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (threatActor.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createThreatActorId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      threatActor.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createThreatActorId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const threatActorDelete = threatActorId => deleteByID(threatActorId);
