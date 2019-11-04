import { ascend, assoc, descend, prop, sortWith, take } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  distribution,
  escape,
  escapeString,
  executeWrite,
  refetchEntityById,
  getSingleValueNumber,
  graknNow,
  monthFormat,
  notify,
  paginate,
  paginateRelationships,
  prepareDate,
  timeSeries,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => {
  if (args.orderBy === 'createdByRef') {
    const finalArgs = assoc('orderBy', 'name', args);
    return paginate(
      `match $r isa Report; 
      ${
        args.reportClass
          ? `$r has report_class "${escapeString(args.reportClass)}";`
          : ''
      } 
      $rel(creator:$x, so:$r) isa created_by_ref`,
      finalArgs,
      true,
      'x'
    );
  }
  if (args.name && args.published) {
    return paginate(
      `match $r isa Report, has name "${escapeString(
        args.name
      )}", has published ${prepareDate(args.published)}`,
      args
    );
  }
  return elPaginate('stix_domain_entities', assoc('type', 'report', args));
};

export const reportsTimeSeries = args =>
  timeSeries(
    `match $x isa Report${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args
  );

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
      ${
        args.reportClass
          ? `$r has report_class "${escapeString(args.reportClass)};"`
          : ''
      }
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
    ${
      args.reportClass
        ? `$r has report_class "${escapeString(args.reportClass)}";`
        : ''
    }
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

export const reportsTimeSeriesByEntity = args =>
  timeSeries(
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

export const reportsTimeSeriesByAuthor = args =>
  timeSeries(
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

export const findById = reportId => refetchEntityById(reportId);

export const objectRefs = (reportId, args) =>
  paginate(
    `match $so isa Stix-Domain-Entity;
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs;
    $r has internal_id_key "${escapeString(reportId)}"`,
    args
  );

export const observableRefs = (reportId, args) =>
  paginate(
    `match $so isa Stix-Observable; 
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id_key "${escapeString(reportId)}"`,
    args
  );

export const relationRefs = (reportId, args) =>
  paginateRelationships(
    `match $rel($from, $to) isa ${
      args.relationType ? args.relationType : 'stix_relation'
    }; 
    $extraRel(so:$rel, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id_key "${escapeString(reportId)}"`,
    args,
    'extraRel'
  );

export const addReport = async (user, report) => {
  const reportId = await executeWrite(async wTx => {
    const internalId = report.internal_id_key
      ? escapeString(report.internal_id_key)
      : uuid();
    const reportIterator = await wTx.tx.query(`insert $report isa Report,
    has internal_id_key "${internalId}",
    has entity_type "report",
    has stix_id_key "${
      report.stix_id_key
        ? escapeString(report.stix_id_key)
        : `report--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(report.name)}",
    has description "${escapeString(report.description)}",
    has published ${prepareDate(report.published)},
    has published_day "${dayFormat(report.published)}",
    has published_month "${monthFormat(report.published)}",
    has published_year "${yearFormat(report.published)}",
    has report_class "${escapeString(report.report_class)}",
    has object_status ${report.object_status ? report.object_status : 0},
    has source_confidence_level ${
      report.source_confidence_level
        ? escape(report.source_confidence_level)
        : 3
    },
    has graph_data "${escapeString(report.graph_data)}",
    has created ${report.created ? prepareDate(report.created) : graknNow()},
    has modified ${report.modified ? prepareDate(report.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",        
    has updated_at ${graknNow()};
  `);
    const createdReport = await reportIterator.next();
    const createdReportId = await createdReport.map().get('report').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdReportId, report.createdByRef);
    await linkMarkingDef(wTx, createdReportId, report.markingDefinitions);
    return internalId;
  });
  return refetchEntityById(reportId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
