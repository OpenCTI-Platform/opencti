import { Promise } from 'bluebird';
import { last } from 'ramda';
import { findAll as findAllTools } from '../domain/tool';
import { stixDomainEntityDelete } from '../domain/stixDomainEntity';
import { logger } from '../config/conf';

export const up = async (next) => {
  try {
    logger.info(`[MIGRATION] clean_cve_tool > Starting cleaning...`);
    logger.info(`[MIGRATION] clean_cve_tool > Cleaning tools in batchs of 200`);
    let hasMore = true;
    let currentCursor = null;
    while (hasMore) {
      logger.info(`[MIGRATION] clean_cve_tool > Cleaning tools at cursor ${currentCursor}`);
      const tools = await findAllTools({
        filters: [{ key: 'name', values: ['CVE-*'], operator: 'match' }],
        first: 200,
        after: currentCursor,
        orderAsc: true,
        orderBy: 'name',
      });
      await Promise.all(
        tools.edges.map((toolEdge) => {
          const tool = toolEdge.node;
          return stixDomainEntityDelete(tool.id);
        })
      );
      if (last(tools.edges)) {
        currentCursor = last(tools.edges).cursor;
        hasMore = tools.pageInfo.hasNextPage;
      } else {
        hasMore = false;
      }
    }
    logger.info(`[MIGRATION] clean_cve_tool > Migration complete`);
  } catch (err) {
    logger.info(`[MIGRATION] clean_cve_tool > Error ${err}`);
  }
  next();
};

export const down = async (next) => {
  next();
};
