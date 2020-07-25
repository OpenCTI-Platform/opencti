import { assoc, pipe } from 'ramda';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  now,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { ABSTRACT_CYBER_OBSERVABLE, ENTITY_TYPE_X_OPENCTI_INCIDENT, RELATION_RELATED_TO } from '../utils/idGenerator';

export const findById = (incidentId) => {
  return loadEntityById(incidentId, 'Incident');
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_X_OPENCTI_INCIDENT], ['name', 'description', 'aliases'], args);
};

// region time series
export const xOpenctiIncidentsTimeSeriesByEntity = async (args) => {
  const filters = [{ isRelation: true, type: args.relationType, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, filters, args);
};

export const xOpenctiIncidentsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_X_OPENCTI_INCIDENT, [], args);
};
// endregion

export const observables = (reportId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_X_OPENCTI_INCIDENT}; 
    $rel(${RELATION_RELATED_TO}_from:$from, ${RELATION_RELATED_TO}_to:$to) isa ${RELATION_RELATED_TO};
    $from isa ${ABSTRACT_CYBER_OBSERVABLE};
    $to has internal_id_key "${escapeString(reportId)}"; get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const addXOpenctiIncident = async (user, incident) => {
  const currentDate = now();
  const incidentToCreate = pipe(
    assoc('first_seen', incident.first_seen ? incident.first_seen : currentDate),
    assoc('last_seen', incident.last_seen ? incident.last_seen : currentDate)
  )(incident);
  const created = await createEntity(user, incidentToCreate, ENTITY_TYPE_X_OPENCTI_INCIDENT);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
