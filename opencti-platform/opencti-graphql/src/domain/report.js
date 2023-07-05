import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import {
  batchListThroughGetTo,
  createEntity,
  distributionEntities,
  internalDeleteElementById,
  listAllThings,
  timeSeriesEntities,
} from '../database/middleware';
import { countAllThings, internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_PARTICIPANT } from '../schema/stixRefRelationship';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  buildRefRelationKey
} from '../schema/general';
import { elCount, ES_MAX_CONCURRENCY } from '../database/engine';
import { READ_DATA_INDICES_WITHOUT_INFERRED, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { stixDomainObjectDelete } from './stixDomainObject';
import { ENTITY_TYPE_USER } from '../schema/internalObject';

export const findById = (context, user, reportId) => {
  return storeLoadById(context, user, reportId, ENTITY_TYPE_CONTAINER_REPORT);
};

export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], args);
};
export const batchParticipants = (context, user, reportIds) => {
  return batchListThroughGetTo(context, user, reportIds, RELATION_OBJECT_PARTICIPANT, ENTITY_TYPE_USER);
};

export const findReportsForObject = async (context, user, objectId, args) => {
  const filters = [...(args.filters ?? []), { key: buildRefRelationKey(RELATION_OBJECT), values: [objectId] }];
  const finalArgs = { ...args, filters };
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], finalArgs);
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
  const filters = reportClass ? [{ key: ['report_class'], values: [args.reportClass] }, ...(args.filters || [])] : args.filters;
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const reportsNumber = (context, user, args) => {
  return {
    count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_REPORT] }),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_REPORT] }
    ),
  };
};

export const reportsTimeSeriesByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const reportsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const reportsNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_REPORT] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER_REPORT] },
    ),
  };
};

export const reportsNumberByAuthor = (context, user, args) => {
  const { authorId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_REPORT] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER_REPORT] },
    ),
  };
};

export const reportsDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};
// endregion

// region mutations
export const addReport = async (context, user, report) => {
  const finalReport = R.assoc('created', report.published, report);
  const created = await createEntity(context, user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// Delete all report contained entities if no other reports are linked
const buildReportDeleteElementsFilter = (reportId) => {
  const refKey = buildRefRelationKey(RELATION_OBJECT);
  return [
    { key: [refKey], values: [reportId] },
    { key: [refKey], values: [`doc['${refKey}.keyword'].length == 1`], operator: 'script' }
  ];
};
export const reportDeleteWithElements = async (context, user, reportId) => {
  // Load all entities and see if they no longer have any report
  const callback = async (objects) => {
    await BluePromise.map(objects, (object) => {
      return internalDeleteElementById(context, context.user, object.id);
    }, { concurrency: ES_MAX_CONCURRENCY });
  };
  // Load all report objects with a callback
  const args = { filters: buildReportDeleteElementsFilter(reportId), callback };
  await listAllThings(context, user, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_RELATIONSHIP], args);
  // Delete the report
  await stixDomainObjectDelete(context, user, reportId);
  return reportId;
};
export const reportDeleteElementsCount = async (context, user, reportId) => {
  const filters = buildReportDeleteElementsFilter(reportId);
  return countAllThings(context, user, { indices: READ_DATA_INDICES_WITHOUT_INFERRED, filters });
};
// endregion
