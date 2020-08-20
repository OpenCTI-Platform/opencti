import { assoc, append, propOr, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escapeString,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  prepareDate,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { findAll as findAllStixDomainEntities } from './stixDomainObject';
import { findById as findIdentityById } from './identity';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_CONTAINER_REPORT,
  RELATION_CREATED_BY,
  RELATION_OBJECT,
} from '../utils/idGenerator';

export const STATUS_STATUS_NEW = 0;
export const STATUS_STATUS_PROGRESS = 1;
export const STATUS_STATUS_ANALYZED = 2;
export const STATUS_STATUS_CLOSED = 3;

export const findById = (reportId) => {
  return loadEntityById(reportId, ENTITY_TYPE_CONTAINER_REPORT);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_REPORT], ['name', 'description'], args);
};

// Entities tab
export const objects = (reportId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [reportId] }, propOr([], 'filters', args)), args);
  return findAllStixDomainEntities(finalArgs);
};

export const reportContainsStixObjectOrStixRelationship = async (reportId, thingId) => {
  const args = {
    filters: [
      { key: 'internal_id', values: [reportId] },
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [thingId] },
    ],
  };
  const reportFound = await findAll(args);
  return reportFound.edges.length > 0;
};

// region series
export const reportsTimeSeries = (args) => {
  const { reportClass } = args;
  const filters = reportClass ? [{ isRelation: false, type: 'report_class', value: args.reportClass }] : [];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

// TODO Migrate to ElasticSearch
export const reportsNumber = (args) => ({
  count: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_CONTAINER_REPORT};
   ${args.reportClass ? `; $x has report_class "${escapeString(args.reportClass)}"` : ''} 
   ${args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''}
   get; count;`),
  total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_CONTAINER_REPORT};
    ${args.reportClass ? `; $x has report_class "${escapeString(args.reportClass)}"` : ''}
    get; count;`),
});

export const reportsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

export const reportsTimeSeriesByAuthor = async (args) => {
  const { authorId, reportClass } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }];
  if (reportClass) filters.push({ isRelation: false, type: 'report_class', value: reportClass });
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

// TODO Migrate to ElasticSearch
export const reportsNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $from isa ${ENTITY_TYPE_CONTAINER_REPORT}, has internal_id $from_id;
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to has internal_id "${escapeString(args.objectId)}"; 
    ${args.reportType ? `$to has report_types "${escapeString(args.reportType)};"` : ''}
    ${args.endDate ? `$to has created_at $date; $date < ${prepareDate(args.endDate)};` : ''}
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $from isa ${ENTITY_TYPE_CONTAINER_REPORT}, has internal_id $from_id;
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $to has internal_id "${escapeString(args.objectId)}";
    ${args.reportType ? `$x has report_class "${escapeString(args.reportType)};"` : ''}
    get;
    count;`
  ),
});

export const reportsDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationshipType', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_CONTAINER_REPORT),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationshipType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};
// endregion

// region mutations
export const addReport = async (user, report) => {
  // Get the reliability of the author
  let confidence = 20;
  if (report.createdBy) {
    const identity = await findIdentityById(report.createdBy);
    if (identity.reliability) {
      switch (identity.reliability) {
        case 'A':
          confidence = 80;
          break;
        case 'B':
          confidence = 60;
          break;
        case 'C':
          confidence = 40;
          break;
        default:
          confidence = 20;
      }
    }
  }
  const finalReport = pipe(
    assoc('x_opencti_report_status', propOr(STATUS_STATUS_NEW, 'x_opencti_report_status', report)),
    assoc('confidence', propOr(confidence, 'confidence', report))
  )(report);
  const created = await createEntity(user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
