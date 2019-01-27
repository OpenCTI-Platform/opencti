import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  notify,
  now,
  paginate,
  prepareDate,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Incident', args);

export const findById = incidentId => loadByID(incidentId);

export const addIncident = async (user, incident) => {
  const wTx = await takeTx();
  const incidentIterator = await wTx.query(`insert $incident isa Incident 
    has type "incident";
    $incident has stix_id "incident--${uuid()}";
    $incident has stix_label "";
    $incident has stix_label_lowercase "";
    $incident has name "${incident.name}";
    $incident has description "${incident.description}";
    $incident has name_lowercase "${incident.name.toLowerCase()}";
    $incident has description_lowercase "${
      incident.description ? incident.description.toLowerCase() : ''
    }";
    $incident has first_seen ${prepareDate(incident.first_seen)};
    $incident has last_seen ${prepareDate(incident.last_seen)};
    $incident has created ${now()};
    $incident has modified ${now()};
    $incident has revoked false;
    $incident has created_at ${now()};
    $incident has updated_at ${now()};
  `);
  const createIncident = await incidentIterator.next();
  const createdIncidentId = await createIncident.map().get('incident').id;

  if (incident.createdByRef) {
    await wTx.query(`match $from id ${createdIncidentId};
         $to id ${incident.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (incident.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdIncidentId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      incident.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdIncidentId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const incidentDelete = incidentId => deleteByID(incidentId);