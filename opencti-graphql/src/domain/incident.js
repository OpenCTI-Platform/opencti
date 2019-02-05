import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  prepareDate,
  takeTx,
  prepareString,
  timeSeries
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Incident', args);

export const incidentsTimeSeries = args =>
  timeSeries('match $x isa Incident', args);

export const findByEntity = args =>
  paginate(
    `match $i isa Incident; 
    $rel($i, $to) isa stix_relation; 
    $to id ${args.objectId}`,
    args
  );

export const incidentsTimeSeriesByEntity = args =>
  timeSeries(
    `match $x isa Incident; 
    $rel($x, $to) isa stix_relation; 
    $to id ${args.objectId}`,
    args
  );

export const findById = incidentId => loadByID(incidentId);

export const addIncident = async (user, incident) => {
  const wTx = await takeTx();
  const incidentIterator = await wTx.query(`insert $incident isa Incident 
    has type "incident";
    $incident has stix_id "incident--${uuid()}";
    $incident has stix_label "";
    $incident has stix_label_lowercase "";
    $incident has alias "";
    $incident has alias_lowercase "";
    $incident has name "${prepareString(incident.name)}";
    $incident has description "${prepareString(incident.description)}";
    $incident has name_lowercase "${prepareString(
      incident.name.toLowerCase()
    )}";
    $incident has description_lowercase "${
      incident.description
        ? prepareString(incident.description.toLowerCase())
        : ''
    }";
    $incident has first_seen ${prepareDate(incident.first_seen)};
    $incident has first_seen_day "${dayFormat(incident.first_seen)}";
    $incident has first_seen_month "${monthFormat(incident.first_seen)}";
    $incident has first_seen_year "${yearFormat(incident.first_seen)}";
    $incident has last_seen ${prepareDate(incident.last_seen)};
    $incident has last_seen_day "${dayFormat(incident.last_seen)}";
    $incident has last_seen_month "${monthFormat(incident.last_seen)}";
    $incident has last_seen_year "${yearFormat(incident.last_seen)}";
    $incident has created ${now()};
    $incident has modified ${now()};
    $incident has revoked false;
    $incident has created_at ${now()};
    $incident has created_at_day "${dayFormat(now())}";
    $incident has created_at_month "${monthFormat(now())}";
    $incident has created_at_year "${yearFormat(now())}";   
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
