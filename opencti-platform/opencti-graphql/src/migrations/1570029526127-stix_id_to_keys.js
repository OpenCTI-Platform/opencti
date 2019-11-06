import uuid from 'uuid/v4';
import { assoc, pipe, splitEvery } from 'ramda';
import {
  attributeExists,
  conceptTypes,
  executeWrite,
  inferIndexFromConceptTypes,
  loadEntityByGraknId
} from '../database/grakn';
import { logger } from '../config/conf';
import { elIndex } from '../database/elasticSearch';

module.exports.up = async next => {
  logger.info(
    `[MIGRATION] stix_id_to_keys > Starting the migration of all STIX_ID to keys... /!\\ This migration could take some time!`
  );
  const entities = [
    'stix_sighting',
    'stix_relation',
    'Stix-Domain',
    'Stix-Observable'
  ];

  logger.info(
    `[MIGRATION] stix_id_to_keys > Migrating all attributes stix_id to stix_id_key...`
  );

  const isExisting = await attributeExists('stix_id');
  if (isExisting) {
    await Promise.all(
      entities.map(async entity => {
        if (entity !== null) {
          logger.info(`[MIGRATION] stix_id_to_keys > Processing ${entity}...`);
          await executeWrite(async wTx => {
            const q = `match $x isa ${entity}, has stix_id $s; not { $x has stix_id_key $sn; }; get;`;
            logger.info(`[MIGRATION] stix_id_to_keys > ${q}`);
            const iterator2 = await wTx.tx.query(q);
            const answers2 = await iterator2.collect();
            const stixIds = [];
            const actionsToDo = await Promise.all(
              answers2.map(async answer => {
                const concept = await answer.map().get('x');
                const types = await conceptTypes(concept);
                const getIndex = inferIndexFromConceptTypes(types);
                const conceptId = await concept.id;
                let entityStixId = await answer
                  .map()
                  .get('s')
                  .value();
                if (stixIds.includes(entityStixId)) {
                  logger.info(
                    `[MIGRATION] stix_id_to_keys > ${entityStixId} is a duplicate, generating a new stix_id`
                  );
                  entityStixId = uuid();
                }
                stixIds.push(entityStixId);
                const graknQuery = `match $x id ${conceptId}; insert $x has stix_id_key "${entityStixId}";`;
                let elasticQuery = null;
                // elReindex if necessary
                if (getIndex) {
                  const attributes = await loadEntityByGraknId(concept.id);
                  const finalAttributes = pipe(
                    assoc('id', entityStixId),
                    assoc('stix_id_key', entityStixId)
                  )(attributes);
                  elasticQuery = { index: getIndex, data: finalAttributes };
                }
                return { id: entityStixId, graknQuery, elasticQuery };
              })
            );
            const actionsBatches = splitEvery(100, actionsToDo);
            for (const actionsBatch of actionsBatches) {
              await Promise.all(
                actionsBatch.map(async action => {
                  logger.info(
                    `[MIGRATION] stix_id_to_keys > ${action.graknQuery}`
                  );
                  if (action.elasticQuery !== null) {
                    logger.info(
                      `[MIGRATION] stix_id_to_keys > Reindex ${action.id}`
                    );
                    await elIndex(
                      action.elasticQuery.index,
                      action.elasticQuery.data
                    );
                  }
                  return wTx.tx.query(action.graknQuery);
                })
              );
            }
            logger.info(
              `[MIGRATION] stix_id_to_keys > Writing ${entity} new key attributes...`
            );
          });
        }
        return false;
      })
    );
  }
  logger.info('[MIGRATION] stix_id_to_keys > Migration complete');
  next();
};

module.exports.down = async next => {
  next();
};
