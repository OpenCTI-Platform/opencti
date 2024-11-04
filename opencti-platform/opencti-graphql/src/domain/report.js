import * as R from 'ramda';
import { createEntity, distributionEntities, internalDeleteElementById, listAllThings, timeSeriesEntities } from '../database/middleware';
import { countAllThings, internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { isEmptyField, READ_DATA_INDICES_WITHOUT_INFERRED, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';
import { stixDomainObjectDelete } from './stixDomainObject';
import { addFilter } from '../utils/filtering/filtering-utils';
import { UnsupportedError } from '../config/errors';

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
    filters: {
      mode: 'and',
      filters: [
        { key: 'internal_id', values: [reportId] },
        { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const reportFound = await findAll(context, user, args);
  return reportFound.edges.length > 0;
};

// region series
export const reportsTimeSeries = (context, user, args) => {
  const { reportClass } = args;
  const filters = reportClass
    ? addFilter(args.filters, 'report_class', args.reportClass)
    : args.filters;
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
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const reportsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};

export const reportsNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
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
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
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
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_REPORT], { ...args, filters });
};
// endregion

// region mutations
export const addReport = async (context, user, report) => {
  if (isEmptyField(report.name) || isEmptyField(report.published)) {
    throw UnsupportedError('Report creation required name and published', { name: report.name, published: report.published });
  }
  const finalReport = R.assoc('created', report.published, report);
  const created = await createEntity(context, user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// Delete all report contained entities if no other reports are linked
const buildReportDeleteElementsFilter = (reportId) => {
  const refKey = buildRefRelationKey(RELATION_OBJECT);
  return {
    mode: 'and',
    filters: [
      { key: [refKey], values: [reportId] },
      { key: [refKey], values: [`doc['${refKey}.keyword'].length == 1`], operator: 'script' }
    ],
    filterGroups: [],
  };
};
export const reportDeleteWithElements = async (context, user, reportId) => {
  // Load all entities & relationships contained only in this report (orphans)
  const args = { filters: buildReportDeleteElementsFilter(reportId) };
  const reportOrphanObjects = await listAllThings(context, user, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_RELATIONSHIP], args);
  // Filter out relationships that will already be deleted with the deletion of the source or target element
  const objectsToDelete = reportOrphanObjects.filter((fo) => !reportOrphanObjects.some((o) => fo.fromId === o.internal_id || fo.toId === o.internal_id));
  for (let i = 0; i < objectsToDelete.length; i += 1) {
    const object = objectsToDelete[i];
    await internalDeleteElementById(context, context.user, object.id);
  }
  // Delete the report
  await stixDomainObjectDelete(context, user, reportId);
  return reportId;
};
export const reportDeleteElementsCount = async (context, user, reportId) => {
  const filters = buildReportDeleteElementsFilter(reportId);
  return countAllThings(context, user, { indices: READ_DATA_INDICES_WITHOUT_INFERRED, filters });
};
// endregion
