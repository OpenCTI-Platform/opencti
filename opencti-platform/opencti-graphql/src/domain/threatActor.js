import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  takeWriteTx,
  getById,
  notify,
  now,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'threat-actor', args));

export const findById = threatActorId => getById(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const wTx = await takeWriteTx();
  const internalId = threatActor.internal_id
    ? escapeString(threatActor.internal_id)
    : uuid();
  const threatActorIterator = await wTx.tx
    .query(`insert $threatActor isa Threat-Actor,
    has internal_id "${internalId}",
    has entity_type "threat-actor",
    has stix_id "${
      threatActor.stix_id
        ? escapeString(threatActor.stix_id)
        : `threat-actor--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(threatActor.name)}", 
    has description "${escapeString(threatActor.description)}",
    has goal "${escapeString(threatActor.goal)}",
    has sophistication "${escapeString(threatActor.sophistication)}",
    has resource_level "${escapeString(threatActor.resource_level)}",
    has primary_motivation "${escapeString(threatActor.primary_motivation)}",
    has secondary_motivation "${escapeString(
      threatActor.secondary_motivation
    )}",
    has personal_motivation "${escapeString(threatActor.personal_motivation)}",
    has created ${
      threatActor.created ? prepareDate(threatActor.created) : now()
    },
    has modified ${
      threatActor.modified ? prepareDate(threatActor.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",        
    has updated_at ${now()};
  `);
  const txThreatActor = await threatActorIterator.next();
  const createThreatActorId = await txThreatActor.map().get('threatActor').id;
  // Create relation createdByRef
  if (threatActor.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createThreatActorId};
      $to has internal_id "${escapeString(threatActor.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }
  // Create Marking definitions relations
  if (threatActor.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createThreatActorId};
        $to has internal_id "${escapeString(markingDefinition)}";
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      threatActor.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  // Finalize the transaction for all objects
  await commitWriteTx(wTx);

  // Return the data created
  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
