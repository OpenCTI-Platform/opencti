import { ascend, assoc, concat, descend, pipe, prop, sortWith, take } from 'ramda';
import {
  createEntity,
  distribution,
  escapeString,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  paginateRelationships,
  prepareDate,
  timeSeries
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findAll as findAllStixDomains } from './stixDomainEntity';
import { findAll as findAllObservables } from './stixObservable';

export const findById = reportId => {
  return loadEntityById(reportId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Report'], args);
  return listEntities(['name', 'description'], typedArgs);
};

// Entities tab
export const objectRefs = async (reportId, args) => {
  const filter = { key: 'object_refs.internal_id_key', values: [reportId] };
  const filters = concat([filter], args.filters || []);
  const finalArgs = pipe(
    assoc('filters', filters),
    assoc('types', ['Stix-Domain-Entity'])
  )(args);
  return findAllStixDomains(finalArgs);
};

export const observableRefs = (reportId, args) => {
  const filter = { key: 'object_refs.internal_id_key', values: [reportId] };
  const filters = concat([filter], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllObservables(filterArgs);
};

// Observables, relations type indicates.
export const relationRefs = async (reportId, args) => {
  const compare = await paginateRelationships(
    `match $rel($from, $to) isa ${args.relationType ? args.relationType : 'stix_relation'};
    $extraRel(so:$rel, knowledge_aggregation:$r) isa object_refs;
    $r has internal_id_key "${escapeString(reportId)}"`,
    args,
    'rel',
    'extraRel'
  );
  return compare;
};

// region series
export const reportsTimeSeries = args => {
  return timeSeries(
    `match $x isa Report${args.reportClass ? `; $x has report_class "${escapeString(args.reportClass)}"` : ''}`,
    args
  );
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
  return timeSeries(
    `match $x isa Report;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args
  );
};
export const reportsTimeSeriesByAuthor = args => {
  return timeSeries(
    `match $x isa Report;
    $rel(so:$x, creator:$so) isa created_by_ref; 
    $so has internal_id_key "${escapeString(args.authorId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args
  );
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
export const reportsDistributionByEntity = args => {
  const { limit = 10 } = args;
  return distribution(
    `match $x isa Report; 
      $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
      $so has internal_id_key "${escapeString(args.objectId)}"`,
    args
  ).then(result => {
    if (args.order === 'asc') {
      return take(limit, sortWith([ascend(prop('value'))])(result));
    }
    return take(limit, sortWith([descend(prop('value'))])(result));
  });
};
// endregion

// region mutations
export const addReport = async (user, report) => {
  const created = await createEntity(report, 'Report');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
// endregion
