import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  takeWriteTx,
  deleteEntityById,
  getById,
  notify,
  now,
  paginate,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString
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

export const findById = threatActorId => getById(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const wTx = await takeWriteTx();
  const threatActorIterator = await wTx.query(`insert $threatActor isa Threat-Actor 
    has type "threat-actor";
    $threatActor has stix_id "${
      threatActor.stix_id
        ? prepareString(threatActor.stix_id)
        : `threat-actor--${uuid()}`
    }";
    $threatActor has stix_label "";
    $threatActor has alias "";
    $threatActor has name "${prepareString(threatActor.name)}";
    $threatActor has description "${prepareString(threatActor.description)}";
    $threatActor has goal "${prepareString(threatActor.goal)}";
    $threatActor has sophistication "${prepareString(
      threatActor.sophistication
    )}";
    $threatActor has resource_level "${prepareString(
      threatActor.resource_level
    )}";
    $threatActor has primary_motivation "${prepareString(
      threatActor.primary_motivation
    )}";
    $threatActor has secondary_motivation "${prepareString(
      threatActor.secondary_motivation
    )}";
    $threatActor has personal_motivation "${prepareString(
      threatActor.personal_motivation
    )}";
    $threatActor has created ${
      threatActor.created ? prepareDate(threatActor.created) : now()
    };
    $threatActor has modified ${
      threatActor.modified ? prepareDate(threatActor.modified) : now()
    };
    $threatActor has revoked false;
    $threatActor has created_at ${now()};
    $threatActor has created_at_day "${dayFormat(now())}";
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

  return getById(createThreatActorId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const threatActorDelete = threatActorId =>
  deleteEntityById(threatActorId);
