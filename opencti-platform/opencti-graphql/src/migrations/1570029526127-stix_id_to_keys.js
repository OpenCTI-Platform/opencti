import uuid from 'uuid/v4';
import { assoc, pipe, splitEvery } from 'ramda';
import {
  takeWriteTx,
  commitWriteTx,
  getAttributes,
  conceptTypes,
  inferIndexFromConceptTypes, attributeExists
} from '../database/grakn';
import { logger } from '../config/conf';
import { index } from '../database/elasticSearch';

module.exports.up = async next => {
  logger.info(
    `[MIGRATION] stix_id_to_keys > Starting the migration of all STIX_ID to keys... /!\\ This migration could take some time!`
  );
  const entities = [
    'stix_relation_embedded',
    'stix_relation_observable_embedded',
    'stix_relation_observable_grouping',
    'stix_sighting',
    'stix_relation',
    'Stix-Domain',
    'Stix-Observable'
  ];

  logger.info(
    `[MIGRATION] stix_id_to_keys > Migrating all attributes stix_id to stix_id_key...`
  );

  const isExisting = await attributeExists('stix_id');
  if (!isExisting) {
    next();
  }

  await Promise.all(
    entities.map(async entity => {
      if (entity !== null) {
        logger.info(`[MIGRATION] stix_id_to_keys > Processing ${entity}...`);
        const wTx = await takeWriteTx();
        const q = `match $x isa ${entity}, has stix_id $s; not { $x has stix_id_key $sn; }; get;`;
        logger.info(`[MIGRATION] stix_id_to_keys > ${q}`);
        const iterator2 = await wTx.tx.query(q);
        const answers2 = await iterator2.collect();
        const stixIds = [];
        const actionsToDo = await Promise.all(
          answers2.map(async answer => {
            const concept = await answer.map().get('x');
            const types = await conceptTypes(concept);
            const getIndex = await inferIndexFromConceptTypes(types);
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
            // reindex if necessary
            if (getIndex) {
              const attributes = await getAttributes(concept);
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
              logger.info(`[MIGRATION] stix_id_to_keys > ${action.graknQuery}`);
              await wTx.tx.query(action.graknQuery);
              if (action.elasticQuery !== null) {
                logger.info(
                  `[MIGRATION] stix_id_to_keys > Reindex ${action.id}`
                );
                await index(
                  action.elasticQuery.index,
                  action.elasticQuery.data
                );
              }
            })
          );
        }
        logger.info(
          `[MIGRATION] stix_id_to_keys > Writing ${entity} new key attributes...`
        );
        await commitWriteTx(wTx);
      }
    })
  );
  logger.info('[MIGRATION] stix_id_to_keys > Migration complete');
  next();
};

module.exports.down = async next => {
  next();
};
