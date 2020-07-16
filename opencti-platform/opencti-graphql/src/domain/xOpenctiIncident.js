import { assoc, pipe } from 'ramda';
import { createEntity, listEntities, loadEntityById, now, timeSeriesEntities } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_X_OPENCTI_INCIDENT } from '../utils/idGenerator';

export const findById = (incidentId) => {
  return loadEntityById(incidentId, 'Incident');
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_X_OPENCTI_INCIDENT], ['name', 'description', 'aliases'], args);
};

// region time series
export const incidentsTimeSeriesByEntity = async (args) => {
  const filters = [{ isRelation: true, type: args.relationType, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, filters, args);
};

export const incidentsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, [], args);
};
// endregion

export const addIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.first_seen ? incident.first_seen : currentDate)
  )(incident);
  const created = await createEntity(user, incidentToCreate, ENTITY_TYPE_X_OPENCTI_INCIDENT);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
