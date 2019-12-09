import { assoc, pipe } from 'ramda';
import {
  createEntity,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  now,
  timeSeriesEntities,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = incidentId => {
  if (incidentId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(incidentId);
  }
  return loadEntityById(incidentId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Incident'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

// region time series
export const incidentsTimeSeriesByEntity = async args => {
  const filters = [{ isRelation: true, type: 'stix_relation', value: args.objectId }];
  return timeSeriesEntities('Incident', filters, args);
};
export const incidentsTimeSeries = args => {
  return timeSeriesEntities('Incident', [], args);
};
// endregion

export const addIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.first_seen ? incident.first_seen : currentDate)
  )(incident);
  const created = await createEntity(incidentToCreate, 'Incident', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'x-opencti-incident'
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
