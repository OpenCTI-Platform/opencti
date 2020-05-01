import { Promise } from 'bluebird';
import { last } from 'ramda';
import { logger } from '../config/conf';
import { findAll } from '../domain/stixObservableRelation';
import { executeWrite, updateAttribute } from '../database/grakn';

const updateRelation = async (stixObservableRelation) => {
  if (stixObservableRelation.entity_type === 'stix_relation') {
    return executeWrite((wTx) => {
      return updateAttribute(
        stixObservableRelation.id,
        'stix_relation',
        {
          key: 'entity_type',
          value: ['stix_observable_relation'],
        },
        wTx
      );
    });
  }
  return Promise.resolve(true);
};

export const up = async (next) => {
  try {
    logger.info(`[MIGRATION] change_bad_entity_type > Starting changing...`);
    logger.info(`[MIGRATION] change_bad_entity_type > Changing stix relations in batchs of 200`);
    let hasMore = true;
    let currentCursor = null;
    while (hasMore) {
      logger.info(`[MIGRATION] change_bad_entity_type > Changing stix relations at cursor ${currentCursor}`);
      const stixObservableRelations = await findAll({
        first: 200,
        after: currentCursor,
        orderAsc: true,
        orderBy: 'created_at',
      });
      await Promise.all(
        stixObservableRelations.edges.map((stixObservableRelationEdge) => {
          const stixObservableRelation = stixObservableRelationEdge.node;
          return updateRelation(stixObservableRelation);
        })
      );
      if (last(stixObservableRelations.edges)) {
        currentCursor = last(stixObservableRelations.edges).cursor;
        hasMore = stixObservableRelations.pageInfo.hasNextPage;
      } else {
        hasMore = false;
      }
    }
    logger.info(`[MIGRATION] change_bad_entity_type > Migration complete`);
  } catch (err) {
    logger.info(`[MIGRATION] change_bad_entity_type`, { error: err });
  }
  next();
};

export const down = async (next) => {
  next();
};
