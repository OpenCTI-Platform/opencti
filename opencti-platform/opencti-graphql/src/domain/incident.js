import { assoc, isNil, pipe } from 'ramda';
import { createEntity, timeSeriesEntities } from '../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INCIDENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { FROM_START, now, UNTIL_END } from '../utils/format';
import { addFilter } from '../utils/filtering/filtering-utils';

export const findById = (context, user, incidentId) => {
  return storeLoadById(context, user, incidentId, ENTITY_TYPE_INCIDENT);
};

export const findIncidentPaginated = (context, user, args) => {
  return listEntitiesPaginated(context, user, [ENTITY_TYPE_INCIDENT], args);
};

// region time series
export const incidentsTimeSeriesByEntity = async (context, user, args) => {
  const { relationship_type, objectId } = args;
  const filters = addFilter(args.filters, relationship_type.map((n) => buildRefRelationKey(n, '*')), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_INCIDENT], { ...args, filters });
};

export const incidentsTimeSeries = (context, user, args) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_INCIDENT], args);
};
// endregion

export const addIncident = async (context, user, incident) => {
  const incidentToCreate = pipe(
    assoc('created', isNil(incident.created) ? now() : incident.created),
    assoc('first_seen', isNil(incident.first_seen) ? new Date(FROM_START) : incident.first_seen),
    assoc('last_seen', isNil(incident.last_seen) ? new Date(UNTIL_END) : incident.last_seen)
  )(incident);
  const created = await createEntity(context, user, incidentToCreate, ENTITY_TYPE_INCIDENT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
