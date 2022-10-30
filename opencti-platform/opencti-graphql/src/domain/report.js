import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import {
  createEntity,
  distributionEntities,
  internalDeleteElementById,
  internalLoadById, listAllThings,
  storeLoadById,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  buildRefRelationKey
} from '../schema/general';
import { elCount, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { stixDomainObjectDelete } from './stixDomainObject';

export const findById = (context, user, reportId) => {
  return storeLoadById(context, user, reportId, ENTITY_TYPE_CONTAINER_REPORT);
};

export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], args);
};

// Entities tab
export const reportContainsStixObjectOrStixRelationship = async (context, user, reportId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [reportId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const reportFound = await findAll(context, user, args);
  return reportFound.edges.length > 0;
};

// region series
export const reportsTimeSeries = (context, user, args) => {
  const { reportClass } = args;
  const filters = reportClass ? [{ isRelation: false, type: 'report_class', value: args.reportClass }] : [];
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsNumber = (context, user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_REPORT]), R.dissoc('endDate'))(args)
  ),
});

export const reportsTimeSeriesByEntity = (context, user, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId, reportClass } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }];
  if (reportClass) filters.push({ isRelation: false, type: 'report_class', value: reportClass });
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsNumberByEntity = (context, user, args) => ({
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

export const reportsNumberByAuthor = (context, user, args) => ({
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

export const reportsDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(context, user, ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};
// endregion

// region mutations
export const addReport = async (context, user, report) => {
  const finalReport = R.assoc('created', report.published, report);
  const created = await createEntity(context, user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// Delete all report contained entities if no other reports are linked
export const reportDeleteWithElements = async (context, user, reportId) => {
  // Load all entities and see if they no longer have any report
  const callback = async (objects) => {
    const filteredObjects = objects.filter((n) => n.object.length === 1);
    await BluePromise.map(filteredObjects, (object) => internalDeleteElementById(context, context.user, object.id), { concurrency: ES_MAX_CONCURRENCY });
  };
  // Load all report objects with a callback
  const args = { filters: [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [reportId] }], callback };
  await listAllThings(context, user, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_RELATIONSHIP], args);
  // Delete the report
  await stixDomainObjectDelete(context, user, reportId);
  return reportId;
};
// endregion
