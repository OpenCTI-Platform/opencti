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

export const reportContainsStixCoreObjectOrStixRelationship = async (reportId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [reportId] },
      { key: 'internal_id', values: [objectId] },
    ],
  };
  const stixCoreObjectsOrStixRelationships = await findAllStixDomainEntities(args);
  return stixCoreObjectsOrStixRelationships.edges.length > 0;
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
  const filters = [{ isRelation: true, from: 'so', to: 'creator', type: RELATION_CREATED_BY, value: authorId }];
  if (reportClass) filters.push({ isRelation: false, type: 'report_class', value: reportClass });
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_REPORT, filters, args);
};

// TODO Migrate to ElasticSearch
export const reportsNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_REPORT};
    $rel(knowledge_aggregation:$x, so:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    } ${
      args.endDate
        ? `; 
    $x has created_at $date;
    $date < ${prepareDate(args.endDate)};`
        : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_REPORT};
    $rel(knowledge_aggregation:$x, so:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ';'
    }
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
  let sourceConfidenceLevel = 1;
  if (report.createdBy) {
    const identity = await findIdentityById(report.createdBy);
    if (identity.reliability) {
      switch (identity.reliability) {
        case 'A':
          sourceConfidenceLevel = 4;
          break;
        case 'B':
          sourceConfidenceLevel = 3;
          break;
        case 'C':
          sourceConfidenceLevel = 2;
          break;
        default:
          sourceConfidenceLevel = 1;
      }
    }
  }
  const finalReport = pipe(
    assoc('object_status', propOr(STATUS_STATUS_NEW, 'object_status', report)),
    assoc('source_confidence_level', propOr(sourceConfidenceLevel, 'source_confidence_level', report))
  )(report);
  const created = await createEntity(user, finalReport, ENTITY_TYPE_CONTAINER_REPORT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
