import { v4 as uuid } from 'uuid';
import { assoc, pipe, splitEvery } from 'ramda';
import { attributeExists, conceptTypes, executeWrite, loadEntityByGraknId } from '../database/grakn';
import { logger } from '../config/conf';
import { elIndex } from '../database/elasticSearch';
import { inferIndexFromConceptTypes } from '../database/utils';

export const up = async (next) => {
  logger.info(
    `[MIGRATION] internal_id_to_keys > Starting the migration of all internal_id to keys... /!\\ This migration could take some time!`
  );
  const entities = [
    'authorize',
    'migrate',
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
    'Group',
    'Workspace',
    'Token',
    'Stix-Domain',
    'Stix-Observable',
    'Stix-Observable-Data',
  ];

  logger.info(`[MIGRATION] internal_id_to_keys > Migrating all attributes internal_id to internal_id_key...`);

  const isExisting = await attributeExists('internal_id');
  if (isExisting) {
    await Promise.all(
      entities.map(async (entity) => {
        if (entity !== null) {
          logger.info(`[MIGRATION] internal_id_to_keys > Processing ${entity}...`);
          await executeWrite(async (wTx) => {
            const q = `match $x isa ${entity}, has internal_id $s; not { $x has internal_id_key $sn; }; get;`;
            logger.info(`[MIGRATION] internal_id_to_keys`, { query: q });
            const iterator2 = await wTx.tx.query(q);
            const answers2 = await iterator2.collect();
            const internalIds = [];
            const actionsToDo = await Promise.all(
              answers2.map(async (answer) => {
                const concept = await answer.map().get('x');
                const types = await conceptTypes(concept);
                const getIndex = inferIndexFromConceptTypes(types);
                const conceptId = await concept.id;
                let entityInternalId = await answer.map().get('s').value();
                if (internalIds.includes(entityInternalId)) {
                  logger.info(
                    `[MIGRATION] internal_id_to_keys > ${entityInternalId} is a duplicate, generating a new internal_id`
                  );
                  entityInternalId = uuid();
                }
                internalIds.push(entityInternalId);
                const graknQuery = `match $x id ${conceptId}; insert $x has internal_id_key "${entityInternalId}";`;
                let elasticQuery = null;
                // elReindex if necessary
                const attributes = await loadEntityByGraknId(concept.id);
                const finalAttributes = pipe(
                  assoc('id', entityInternalId),
                  assoc('internal_id_key', entityInternalId)
                )(attributes);
                elasticQuery = { index: getIndex, data: finalAttributes };
                return { id: entityInternalId, graknQuery, elasticQuery };
              })
            );
            const actionsBatches = splitEvery(100, actionsToDo);
            // eslint-disable-next-line no-restricted-syntax
            for (const actionsBatch of actionsBatches) {
              // eslint-disable-next-line no-await-in-loop
              await Promise.all(
                actionsBatch.map(async (action) => {
                  logger.info(`[MIGRATION] internal_id_to_keys > ${action.graknQuery}`);
                  if (action.elasticQuery !== null) {
                    logger.info(`[MIGRATION] internal_id_to_keys > Reindex ${action.id}`);
                    await elIndex(action.elasticQuery.index, action.elasticQuery.data, true);
                  }
                  return wTx.tx.query(action.graknQuery);
                })
              );
            }
            logger.info(`[MIGRATION] internal_id_to_keys > Writing ${entity} new key attributes...`);
          });
        }
        return false;
      })
    );
  }
  logger.info('[MIGRATION] internal_id_to_keys > Migration complete');
  next();
};

export const down = async (next) => {
  next();
};
