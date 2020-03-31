import { Promise } from 'bluebird';
import { last } from 'ramda';
import { executeWrite, updateAttribute } from '../database/grakn';
import { findAll as findAllStixDomainEntities } from '../domain/stixDomainEntity';
import { logger } from '../config/conf';

export const up = async (next) => {
  try {
    logger.info(`[MIGRATION] update_stix_id_identities > Starting updating...`);
    logger.info(`[MIGRATION] update_stix_id_identities > Updating identities in batchs of 200`);
    await Promise.all(
      ['sector', 'organization', 'user', 'region', 'country', 'city'].map(async (entityType) => {
        let hasMore = true;
        let currentCursor = null;
        while (hasMore) {
          logger.info(`[MIGRATION] update_stix_id_identities > Updating identities at cursor ${currentCursor}`);
          const entities = await findAllStixDomainEntities({
            filters: [{ key: 'stix_id_key', values: [`${entityType}_*`], operator: 'match' }],
            first: 200,
            after: currentCursor,
            orderAsc: true,
            orderBy: 'name',
          });
          await Promise.all(
            entities.edges.map((entityEdge) => {
              const entity = entityEdge.node;
              return executeWrite((wTx) => {
                return updateAttribute(
                  entity.id,
                  'Identity',
                  {
                    key: 'stix_id_key',
                    value: [entity.stix_id_key.replace(entityType, 'identity')],
                  },
                  wTx
                );
              });
            })
          );
          if (last(entities.edges)) {
            currentCursor = last(entities.edges).cursor;
            hasMore = entities.pageInfo.hasNextPage;
          } else {
            hasMore = false;
          }
        }
        return true;
      })
    );
    logger.info(`[MIGRATION] update_stix_id_identities > Migration complete`);
  } catch (err) {
    logger.info(`[MIGRATION] update_stix_id_identities > Error ${err}`);
  }
  next();
};

export const down = async (next) => {
  next();
};
