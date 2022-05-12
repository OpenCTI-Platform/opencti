import * as R from 'ramda';
import {
  createEntity,
  distributionEntities,
  internalLoadById,
  storeLoadById,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';

export const STATUS_STATUS_NEW = 0;
export const STATUS_STATUS_PROGRESS = 1;
export const STATUS_STATUS_ANALYZED = 2;
export const STATUS_STATUS_CLOSED = 3;

export const findById = (user, reportId) => {
  return storeLoadById(user, reportId, ENTITY_TYPE_CONTAINER_REPORT);
};

export const findAll = async (user, args) => {
  return listEntities(user, [ENTITY_TYPE_CONTAINER_REPORT], args);
};

// Entities tab
export const reportContainsStixObjectOrStixRelationship = async (user, reportId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [reportId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const reportFound = await findAll(user, args);
  return reportFound.edges.length > 0;
};

// region series
export const reportsTimeSeries = (user, args) => {
  const { reportClass } = args;
  const filters = reportClass ? [{ isRelation: false, type: 'report_class', value: args.reportClass }] : [];
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]), R.dissoc('endDate'))(args)
  ),
});

export const reportsTimeSeriesByEntity = (user, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsTimeSeriesByAuthor = async (user, args) => {
  const { authorId, reportClass } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }];
  if (reportClass) filters.push({ isRelation: false, type: 'report_class', value: reportClass });
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsNumberByEntity = (user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const reportsNumberByAuthor = (user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]),
      R.assoc('relationshipType', RELATION_CREATED_BY),
      R.assoc('fromId', args.authorId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]),
      R.assoc('relationshipType', RELATION_CREATED_BY),
      R.assoc('fromId', args.authorId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const reportsDistributionByEntity = async (user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};
// endregion

// region mutations
export const addReport = async (user, report) => {
  const finalReport = R.assoc('created', report.published, report);
  const created = await createEntity(user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
