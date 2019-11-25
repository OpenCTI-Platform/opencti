import { ascend, assoc, descend, prop, sortWith, take } from 'ramda';
import {
  createEntity,
  distribution,
  escape,
  escapeString,
  findWithConnectedRelations,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  paginateRelationships,
  prepareDate,
  timeSeries
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = reportId => {
  return loadEntityById(reportId);
};
export const findAll = async args => {
  const typedArgs = assoc('types', ['Report'], args);
  return listEntities(['name', 'description'], typedArgs);
};

// Entities tab
export const objectRefs = (reportId, args) => {
  return findWithConnectedRelations(
    `match $from isa Report; $rel(knowledge_aggregation:$from, so:$to) isa object_refs;
    $to isa ${args.type ? escape(args.type) : 'Stix-Domain-Entity'};
    $from has internal_id_key "${escapeString(reportId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

export const observableRefs = reportId => {
  return findWithConnectedRelations(
    `match $from isa Report; $rel(knowledge_aggregation:$from, so:$to) isa object_refs;
    $to isa Stix-Observable;
    $from has internal_id_key "${escapeString(reportId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

// Observables, relations type indicates.
export const relationRefs = async (reportId, args) => {
  return paginateRelationships(
    `match $rel($from, $to) isa ${args.relationType ? args.relationType : 'stix_relation'};
    $extraRel(so:$rel, knowledge_aggregation:$r) isa object_refs;
    $r has internal_id_key "${escapeString(reportId)}"`,
    args,
    'rel',
    'extraRel'
  );
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
