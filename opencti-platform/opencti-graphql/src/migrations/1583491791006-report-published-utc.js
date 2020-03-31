import { filter, map } from 'ramda';
import { Promise } from 'bluebird';
import { findAll } from '../domain/report';
import { dayFormat, executeWrite, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async (next) => {
  const reports = await findAll();
  // For each report we need to force update
  if (reports && reports.edges) {
    const reportNodes = map((report) => report.node, reports.edges);
    const reportsToModify = filter((r) => {
      const expectedPublishedDay = dayFormat(r.published);
      const currentPublishedDay = r.published_day;
      return expectedPublishedDay === currentPublishedDay;
    }, reportNodes);
    logger.info(`[MIGRATION] report-published-utc > ${reportsToModify.length} reports to modify`);
    await Promise.map(
      reportsToModify,
      (report) => {
        return executeWrite((wTx) => {
          return updateAttribute(
            report.id,
            'Report',
            {
              key: 'published',
              value: [report.published],
            },
            wTx,
            { forceUpdate: true } // Need to force update because the impact is on sub dates of published
          );
        });
      },
      { concurrency: 3 }
    );
  }
  next();
};

export const down = async (next) => {
  next();
};
