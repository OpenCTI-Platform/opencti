import uuid from 'uuid/v4';
import { pipe, assoc, splitEvery } from 'ramda';
import {
  takeWriteTx,
  commitWriteTx,
  getAttributes,
  conceptTypes,
  inferIndexFromConceptTypes
} from '../database/grakn';
import { logger } from '../config/conf';
import { index } from '../database/elasticSearch';

module.exports.up = async next => {
  logger.info(
    `[MIGRATION] internal_id_to_keys > Starting the migration of all internal_id to keys... /!\\ This migration could take some time!`
  );
  const entities = [
    'authorize',
    'migrate',
    'exports',
    'membership',
    'permission',
    'user_permission',
    'relation_embedded',
    'stix_relation_embedded',
    'stix_relation_observable_embedded',
    'stix_relation_observable_grouping',
    'stix_sighting',
    'stix_relation',
    'MigrationStatus',
    'MigrationReference',
    'Settings',
    'Export',
    'Group',
    'Workspace',
    'Token',
    'Stix-Domain',
    'Stix-Observable',
    'Stix-Observable-Data'
  ];

  logger.info(
    `[MIGRATION] internal_id_to_keys > Migrating all attributes internal_id to internal_id_key...`
  );
  await Promise.all(
    entities.map(async entity => {
      if (entity !== null) {
        logger.info(
          `[MIGRATION] internal_id_to_keys > Processing ${entity}...`
        );
        const wTx = await takeWriteTx();
        const q = `match $x isa ${entity}, has internal_id $s; not { $x has internal_id_key $sn; }; get;`;
        logger.info(`[MIGRATION] internal_id_to_keys > ${q}`);
        const iterator2 = await wTx.tx.query(q);
        const answers2 = await iterator2.collect();
        const internalIds = [];
        const actionsToDo = await Promise.all(
          answers2.map(async answer => {
            const concept = await answer.map().get('x');
            const types = await conceptTypes(concept);
            const getIndex = await inferIndexFromConceptTypes(types);
            const conceptId = await concept.id;
            let entityInternalId = await answer
              .map()
              .get('s')
              .value();
            if (internalIds.includes(entityInternalId)) {
              logger.info(
                `[MIGRATION] internal_id_to_keys > ${entityInternalId} is a duplicate, generating a new internal_id`
              );
              entityInternalId = uuid();
            }
            internalIds.push(entityInternalId);
            const graknQuery = `match $x id ${conceptId}; insert $x has internal_id_key "${entityInternalId}";`;
            let elasticQuery = null;
            // reindex if necessary
            if (getIndex) {
              const attributes = await getAttributes(concept);
              const finalAttributes = pipe(
                assoc('id', entityInternalId),
                assoc('internal_id_key', entityInternalId)
              )(attributes);
              elasticQuery = { index: getIndex, data: finalAttributes };
            }
            return { id: entityInternalId, graknQuery, elasticQuery };
          })
        );

        const actionsBatches = splitEvery(100, actionsToDo);
        for (const actionsBatch of actionsBatches) {
          await Promise.all(
            actionsBatch.map(async action => {
              logger.info(
                `[MIGRATION] internal_id_to_keys > ${action.graknQuery}`
              );
              await wTx.tx.query(action.graknQuery);
              if (action.elasticQuery !== null) {
                logger.info(
                  `[MIGRATION] internal_id_to_keys > Reindex ${action.id}`
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
          `[MIGRATION] internal_id_to_keys > Writing ${entity} new key attributes...`
        );
        await commitWriteTx(wTx);
      }
    })
  );
  logger.info('[MIGRATION] internal_id_to_keys > Migration complete');
  next();
};

module.exports.down = async next => {
  next();
};
