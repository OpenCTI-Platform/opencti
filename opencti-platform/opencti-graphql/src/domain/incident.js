import { assoc, pipe } from 'ramda';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  now,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination, TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (incidentId) => {
  if (incidentId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(incidentId, 'Incident');
  }
  return loadEntityById(incidentId, 'Incident');
};
export const findAll = (args) => {
  return listEntities(['Incident'], ['name', 'alias'], args);
};

// region time series
export const incidentsTimeSeriesByEntity = async (args) => {
  const filters = [{ isRelation: true, type: args.relationType, value: args.objectId }];
  return timeSeriesEntities('Incident', filters, args);
};
export const incidentsTimeSeries = (args) => {
  return timeSeriesEntities('Incident', [], args);
};
// endregion

// Observable refs
export const observableRefs = (reportId) => {
  return findWithConnectedRelations(
    `match $to isa Incident; $rel(relate_from:$from, relate_to:$to) isa related-to;
    $from isa Stix-Observable;
    $to has internal_id_key "${escapeString(reportId)}"; get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const addIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.first_seen ? incident.first_seen : currentDate)
  )(incident);
  const created = await createEntity(user, incidentToCreate, 'Incident', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'x-opencti-incident',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
