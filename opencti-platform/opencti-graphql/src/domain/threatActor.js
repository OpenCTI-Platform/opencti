import { assoc } from 'ramda';
import uuid from 'uuid/v4';
import {
  commitWriteTx,
  dayFormat,
  escapeString,
  getById,
  graknNow,
  monthFormat,
  notify,
  prepareDate,
  takeWriteTx,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'threat-actor', args));

export const findById = threatActorId => getById(threatActorId);

export const addThreatActor = async (user, threatActor) => {
  const wTx = await takeWriteTx();
  const internalId = threatActor.internal_id_key
    ? escapeString(threatActor.internal_id_key)
    : uuid();
  const stixId = threatActor.stix_id_key
    ? escapeString(threatActor.stix_id_key)
    : `threat-actor--${uuid()}`;
  const threatActorIterator = await wTx.tx
    .query(`insert $threatActor isa Threat-Actor,
    has internal_id_key "${internalId}",
    has entity_type "threat-actor",
    has stix_id_key "${stixId}",
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
      threatActor.created ? prepareDate(threatActor.created) : graknNow()
    },
    has modified ${
      threatActor.modified ? prepareDate(threatActor.modified) : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",        
    has updated_at ${graknNow()};
  `);
  const txThreatActor = await threatActorIterator.next();
  const createId = await txThreatActor.map().get('threatActor').id;

  // Create associated relations
  await linkCreatedByRef(wTx, createId, threatActor.createdByRef);
  await linkMarkingDef(wTx, createId, threatActor.markingDefinitions);

  // Commit everything and return the data
  await commitWriteTx(wTx);
  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
