import { assoc, pipe } from 'ramda';
import { createEntity, listEntities, loadById, now, timeSeriesEntities } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_X_OPENCTI_INCIDENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (incidentId) => {
  return loadById(incidentId, ENTITY_TYPE_X_OPENCTI_INCIDENT);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_X_OPENCTI_INCIDENT], args);
};

// region time series
export const xOpenCTIIncidentsTimeSeriesByEntity = async (args) => {
  const filters = [{ isRelation: true, type: args.relationship_type, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, filters, args);
};

export const xOpenCTIIncidentsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, [], args);
};
// endregion

export const addXOpenCTIIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.last_seen ? incident.last_seen : currentDate)
  )(incident);
  const created = await createEntity(user, incidentToCreate, ENTITY_TYPE_X_OPENCTI_INCIDENT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
