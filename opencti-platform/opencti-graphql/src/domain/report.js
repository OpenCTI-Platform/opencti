import { ascend, assoc, descend, prop, sortWith, take } from 'ramda';
import {
  createEntity,
  distribution,
  escapeString,
  getSingleValueNumber,
  loadEntityById,
  paginate,
  paginateRelationships,
  prepareDate,
  timeSeries
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = reportId => {
  return loadEntityById(reportId);
};
export const findAll = args => {
  if (args.orderBy === 'createdByRef') {
    const finalArgs = assoc('orderBy', 'name', args);
    return paginate(
      `match $r isa Report; 
      ${args.reportClass ? `$r has report_class "${escapeString(args.reportClass)}";` : ''} 
      $rel(creator:$x, so:$r) isa created_by_ref`,
      finalArgs,
      true,
      'x'
    );
  }
  if (args.name && args.published) {
    return paginate(
      `match $r isa Report, has name "${escapeString(args.name)}", has published ${prepareDate(args.published)}`,
      args
    );
  }
  return elPaginate('stix_domain_entities', assoc('type', 'report', args));
};
export const reportsTimeSeries = args => {
  return timeSeries(
    `match $x isa Report${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args
  );
};
export const reportsNumber = args => ({
  count: getSingleValueNumber(
    `match $x isa Report;
   ${
     args.reportClass
       ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
       : ''
   } ${
      args.endDate
        ? `$x has created_at $date;
    $date < ${prepareDate(args.endDate)};`
        : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa Report;
    ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    }
    get;
    count;`
  )
});
export const findByEntity = args => {
  if (args.orderBy === 'createdByRef') {
    const finalArgs = assoc('orderBy', 'name', args);
    return paginate(
      `match $r isa Report; 
      ${args.reportClass ? `$r has report_class "${escapeString(args.reportClass)};"` : ''}
      ${
        args.search
          ? `$r has name $name; $r has description $desc; { $name contains "${escapeString(
              args.search
            )}"; } or { $desc contains "${escapeString(args.search)}"; };`
          : ''
      }
      $rel(knowledge_aggregation:$r, so:$so) isa object_refs; 
      $so has internal_id_key "${escapeString(args.objectId)}";
      $relCreatedByRef(creator:$x, so:$r) isa created_by_ref`,
      finalArgs,
      true,
      'x',
      true
    );
  }
  return paginate(
    `match $r isa Report; 
    ${args.reportClass ? `$r has report_class "${escapeString(args.reportClass)}";` : ''}
    ${
      args.search
        ? `$r has name $name; $r has description $desc; { $name contains "${escapeString(
            args.search
          )}"; } or { $desc contains "${escapeString(args.search)}"; };`
        : ''
    }
    $rel(knowledge_aggregation:$r, so:$so) isa object_refs; 
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args,
    true,
    null,
    true
  );
};
export const findByAuthor = args => {
  return paginate(
    `match $r isa Report; 
    $rel(so:$r, creator:$so) isa created_by_ref; 
    $so has internal_id_key "${escapeString(args.authorId)}" ${
      args.reportClass
        ? `; 
    $r has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args,
    true,
    null,
    true
  );
};
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
export const objectRefs = (reportId, args) => {
  return paginate(
    `match $so isa Stix-Domain-Entity;
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs;
    $r has internal_id_key "${escapeString(reportId)}"`,
    args
  );
};
export const observableRefs = (reportId, args) => {
  return paginate(
    `match $so isa Stix-Observable; 
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id_key "${escapeString(reportId)}"`,
    args
  );
};
export const relationRefs = (reportId, args) => {
  return paginateRelationships(
    `match $rel($from, $to) isa ${args.relationType ? args.relationType : 'stix_relation'}; 
    $extraRel(so:$rel, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id_key "${escapeString(reportId)}"`,
    args,
    'extraRel'
  );
};

export const addReport = async (user, report) => {
  const created = await createEntity(report, 'Report');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
