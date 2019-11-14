import { assoc, pipe } from 'ramda';
import {
  createEntity,
  escapeString,
  loadEntityById,
  now,
  paginate,
  timeSeries,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = incidentId => {
  return loadEntityById(incidentId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'incident', args));
};

// grakn fetch
export const incidentsTimeSeries = args => {
  return timeSeries('match $i isa Incident', args);
};
export const findByEntity = args => {
  return paginate(
    `match $x isa Incident;
    $rel($x, $to) isa stix_relation;
    $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};
export const incidentsTimeSeriesByEntity = args => {
  return timeSeries(
    `match $x isa Incident; 
    $rel($x, $to) isa stix_relation; 
    $to has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};
// endregion

export const addIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.first_seen ? incident.first_seen : currentDate)
  )(incident);
  const created = await createEntity(incidentToCreate, 'Incident', TYPE_STIX_DOMAIN_ENTITY, 'x-opencti-incident');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
