import { assoc, append, propOr } from 'ramda';
import {
  createEntity,
  distributionEntities,
  escape,
  escapeString,
  findWithConnectedRelations,
  getSingleValueNumber,
  listEntities,
  listRelations,
  loadEntityById,
  loadEntityByStixId,
  prepareDate,
  timeSeriesEntities
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { findAll as findAllStixObservables } from './stixObservable';
import { findAll as findAllStixDomainEntities } from './stixDomainEntity';

export const findById = reportId => {
  if (reportId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(reportId);
  }
  return loadEntityById(reportId);
};
export const findAll = async args => {
  return listEntities(['Report'], ['name', 'description'], args);
};

// Entities tab
export const objectRefs = (reportId, args) => {
  if (args.orderBy || args.filters || args.search) {
    const finalArgs = assoc(
      'filters',
      append(
        { key: `${REL_INDEX_PREFIX}object_refs.internal_id_key`, values: [reportId] },
        propOr([], 'filters', args)
      ),
      args
    );
    return findAllStixDomainEntities(finalArgs);
  }
  return findWithConnectedRelations(
    `match $from isa Report; $rel(knowledge_aggregation:$from, so:$to) isa object_refs;
    $to isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
    $from has internal_id_key "${escapeString(reportId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
// Relation refs
export const relationRefs = (reportId, args) => {
  const pointingFilter = { relation: 'object_refs', fromRole: 'so', toRole: 'knowledge_aggregation', id: reportId };
  return listRelations(args.relationType, pointingFilter, args);
};
// Observable refs
export const observableRefs = (reportId, args) => {
  if (args.orderBy || args.filters || args.search) {
    const finalArgs = assoc(
      'filters',
      append(
        { key: `${REL_INDEX_PREFIX}observable_refs.internal_id_key`, values: [reportId] },
        propOr([], 'filters', args)
      ),
      args
    );
    return findAllStixObservables(finalArgs);
  }
  return findWithConnectedRelations(
    `match $from isa Report; $rel(observables_aggregation:$from, soo:$to) isa observable_refs;
    $to isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
    $from has internal_id_key "${escapeString(reportId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

// region series
export const reportsTimeSeries = args => {
  const { reportClass } = args;
  const filters = reportClass ? [{ isRelation: false, type: 'report_class', value: args.reportClass }] : [];
  return timeSeriesEntities('Incident', filters, args);
};
export const reportsNumber = args => ({
  count: getSingleValueNumber(`match $x isa Report;
   ${args.reportClass ? `; $x has report_class "${escapeString(args.reportClass)}"` : ''} 
   ${args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''}
   get; count;`),
  total: getSingleValueNumber(`match $x isa Report;
    ${args.reportClass ? `; $x has report_class "${escapeString(args.reportClass)}"` : ''}
    get; count;`)
});
export const reportsTimeSeriesByEntity = args => {
  const filters = [{ isRelation: true, type: 'object_refs', value: args.objectId }];
  return timeSeriesEntities('Report', filters, args);
};
export const reportsTimeSeriesByAuthor = async args => {
  const { authorId, reportClass } = args;
  const filters = [{ isRelation: true, from: 'so', to: 'creator', type: 'created_by_ref', value: authorId }];
  if (reportClass) filters.push({ isRelation: false, type: 'report_class', value: reportClass });
  return timeSeriesEntities('Report', filters, args);
};
export const reportsNumberByEntity = args => ({
  count: getSingleValueNumber(
    `match $x isa Report;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}" ${
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
    `match $x isa Report;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ';'
    }
    get;
    count;`
  )
});
export const reportsDistributionByEntity = async args => {
  const { objectId } = args;
  const filters = [{ isRelation: true, from: 'knowledge_aggregation', to: 'so', type: 'object_refs', value: objectId }];
  return distributionEntities('Report', filters, args);
};
// endregion

// region mutations
export const addReport = async (user, report) => {
  const created = await createEntity(report, 'Report');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
// endregion
