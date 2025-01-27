import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { createStatus, createStatusTemplate } from '../domain/status';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Creating the report workflow statuses');
  const statusNew = await createStatusTemplate(context, SYSTEM_USER, { name: 'NEW', color: '#ff9800' });
  const statusInProgress = await createStatusTemplate(context, SYSTEM_USER, { name: 'IN_PROGRESS', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'PENDING', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'TO_BE_QUALIFIED', color: '#5c7bf5' });
  const statusAnalyzed = await createStatusTemplate(context, SYSTEM_USER, { name: 'ANALYZED', color: '#4caf50' });
  const statusClosed = await createStatusTemplate(context, SYSTEM_USER, { name: 'CLOSED', color: '#607d8b' });
  const workflowStatusNew = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, {
    template_id: statusNew.id,
    order: 1
  });
  const workflowStatusInProgress = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, {
    template_id: statusInProgress.id,
    order: 2
  });
  const workflowStatusAnalyzed = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, {
    template_id: statusAnalyzed.id,
    order: 3
  });
  const workflowStatusClosed = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, {
    template_id: statusClosed.id,
    order: 4
  });
  logApp.info('[MIGRATION] Migrate and clean current reports');
  const bulkOperations = [];
  const callback = (reports) => {
    const op = reports
      .map((report) => {
        let status;
        switch (report.x_opencti_report_status) {
          case 0:
            status = workflowStatusNew;
            break;
          case 1:
            status = workflowStatusInProgress;
            break;
          case 2:
            status = workflowStatusAnalyzed;
            break;
          default:
            status = workflowStatusClosed;
        }
        return [{ update: { _index: report._index, _id: report._id } }, { doc: { status_id: status.id } }];
      })
      .flat();
    bulkOperations.push(...op);
  };
  const opts = { types: [ENTITY_TYPE_CONTAINER_REPORT], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Migrating reports ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Migrating reports done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
