import { map, assoc, sortWith, take, ascend, descend, prop } from 'ramda';
import uuid from 'uuid/v4';
import {
  escape,
  escapeString,
  getById,
  notify,
  now,
  paginate,
  paginateRelationships,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  takeWriteTx,
  timeSeries,
  getSingleValueNumber,
  distribution,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args => {
  if (args.orderBy === 'createdByRef') {
    const finalArgs = assoc('orderBy', 'name', args);
    return paginate(
      `match $r isa Report; 
      ${
        args.reportClass
          ? `$r has report_class "${escapeString(args.reportClass)};"`
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
  return elPaginate('stix-domain-entities', assoc('type', 'report', args));
  /*
  return paginate(
    `match $r isa Report${
      args.reportClass
        ? `; 
    $r has report_class "${escapeString(args.reportClass)}"`
        : ''
    }`,
    args
  ); */
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
      $rel(knowledge_aggregation:$r, so:$so) isa object_refs; 
      $so has internal_id "${escapeString(args.objectId)}";
      $relCreatedByRef(creator:$x, so:$r) isa created_by_ref`,
      finalArgs,
      true,
      'x',
      true
    );
  }
  return paginate(
    `match $r isa Report; 
    $rel(knowledge_aggregation:$r, so:$so) isa object_refs; 
    $so has internal_id "${escapeString(args.objectId)}" ${
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

export const findByAuthor = args => {
  return paginate(
    `match $r isa Report; 
    $rel(so:$r, creator:$so) isa created_by_ref; 
    $so has internal_id "${escapeString(args.authorId)}" ${
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
    $so has internal_id "${escapeString(args.objectId)}" ${
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
    $so has internal_id "${escapeString(args.authorId)}" ${
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
    get $x;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa Report;
    $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.reportClass
        ? `; 
    $x has report_class "${escapeString(args.reportClass)}"`
        : ';'
    }
    get $x;
    count;`
  )
});

export const reportsDistributionByEntity = args => {
  const { limit = 10 } = args;
  return distribution(
    `match $x isa Report; 
      $rel(knowledge_aggregation:$x, so:$so) isa object_refs; 
      $so has internal_id "${escapeString(args.objectId)}"`,
    args
  ).then(result => {
    if (args.order === 'asc') {
      return take(limit, sortWith([ascend(prop('value'))])(result));
    }
    return take(limit, sortWith([descend(prop('value'))])(result));
  });
};

export const findById = reportId => getById(reportId);

export const objectRefs = (reportId, args) =>
  paginate(
    `match $so isa Stix-Domain-Entity;
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs;
    $r has internal_id "${escapeString(reportId)}"`,
    args
  );

export const observableRefs = (reportId, args) =>
  paginate(
    `match $so isa Stix-Observable; 
    $rel(so:$so, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id "${escapeString(reportId)}"`,
    args
  );

export const relationRefs = (reportId, args) =>
  paginateRelationships(
    `match $rel($from, $to) isa ${
      args.relationType ? args.relationType : 'stix_relation'
    }; 
    $extraRel(so:$rel, knowledge_aggregation:$r) isa object_refs; 
    $r has internal_id "${escapeString(reportId)}"`,
    args,
    'extraRel'
  );

export const addReport = async (user, report) => {
  const wTx = await takeWriteTx();
  const internalId = report.internal_id
    ? escapeString(report.internal_id)
    : uuid();
  const reportIterator = await wTx.tx.query(`insert $report isa Report,
    has internal_id "${internalId}",
    has entity_type "report",
    has stix_id "${
      report.stix_id ? escapeString(report.stix_id) : `report--${uuid()}`
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
    has created ${report.created ? prepareDate(report.created) : now()},
    has modified ${report.modified ? prepareDate(report.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",        
    has updated_at ${now()};
  `);
  const createdReport = await reportIterator.next();
  const createdReportId = await createdReport.map().get('report').id;

  if (report.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdReportId};
      $to has internal_id "${escapeString(report.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (report.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdReportId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      report.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
