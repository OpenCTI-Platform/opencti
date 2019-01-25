import { map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qkObjUnique,
  prepareDate,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Report', args);
export const findAllByClass = args =>
  paginate(
    `match $m isa Report; $m has report_class "${args.reportClass}"`,
    args
  );
export const findAllBySo = args =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$so) isa object_refs; 
    $so id ${args.objectId}`,
    args
  );
export const findAllBySoAndClass = args =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$so) isa object_refs;
    $so id ${args.objectId};
    $report has report_class "${args.reportClass}"`,
    args
  );

export const findById = reportId => loadByID(reportId);

export const createdByRef = reportId =>
  qkObjUnique(
    `match $x isa Identity; 
    $rel(creator:$x, so:$report) isa created_by_ref; 
    $report id ${reportId};  offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const markingDefinitions = (reportId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$report) isa object_marking_refs; 
    $report id ${reportId}`,
    args
  );

export const objectRefs = (reportId, args) =>
  paginate(
    `match $so isa Stix-Domain-Entity; 
    $rel(so:$so, knowledge_aggregation:$report) isa object_refs; 
    $report id ${reportId}`,
    args
  );

export const addReport = async (user, report) => {
  const wTx = await takeTx();
  const reportIterator = await wTx.query(`insert $report isa Report 
    has type "report";
    $report has stix_id "report--${uuid()}";
    $report has stix_label "";
    $report has name "${report.name}";
    $report has description "${report.description}";
    $report has name_lowercase "${report.name.toLowerCase()}";
    $report has description_lowercase "${
      report.description ? report.description.toLowerCase() : ''
    }";
    $report has published ${prepareDate(report.published)};
    $report has report_class "${report.report_class}";
    $report has graph_data "";
    $report has created ${now()};
    $report has modified ${now()};
    $report has revoked false;
    $report has created_at ${now()};
    $report has updated_at ${now()};
  `);
  const createdReport = await reportIterator.next();
  const createdReportId = await createdReport.map().get('report').id;

  if (report.createdByRef) {
    await wTx.query(`match $from id ${createdReportId};
         $to id ${report.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (report.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdReportId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      report.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdReportId).then(created =>
    notify(BUS_TOPICS.Report.ADDED_TOPIC, created, user)
  );
};

export const reportDelete = reportId => deleteByID(reportId);

export const reportAddRelation = (user, reportId, input) =>
  createRelation(reportId, input).then(relationData => {
    notify(BUS_TOPICS.Report.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const reportDeleteRelation = (user, reportId, relationId) =>
  deleteRelation(reportId, relationId).then(relationData => {
    notify(BUS_TOPICS.Report.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const reportCleanContext = (user, reportId) => {
  delEditContext(user, reportId);
  return loadByID(reportId).then(report =>
    notify(BUS_TOPICS.Report.EDIT_TOPIC, report, user)
  );
};

export const reportEditContext = (user, reportId, input) => {
  setEditContext(user, reportId, input);
  return loadByID(reportId).then(report =>
    notify(BUS_TOPICS.Report.EDIT_TOPIC, report, user)
  );
};

export const reportEditField = (user, reportId, input) =>
  editInputTx(reportId, input).then(report =>
    notify(BUS_TOPICS.Report.EDIT_TOPIC, report, user)
  );
