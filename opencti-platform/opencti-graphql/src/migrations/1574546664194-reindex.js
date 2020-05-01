import { executeWrite, internalDirectWrite } from '../database/grakn';
import index from '../database/indexing';
import { logger } from '../config/conf';

export const up = async (next) => {
  logger.info(`[MIGRATION] reindex > Deleting potential orphan relations, this operation could take some time...`);
  logger.info(`[MIGRATION] reindex > Delete related-to same origin/target`);
  try {
    await executeWrite((wTx) => {
      wTx.tx.query(
        `match $x isa related-to; $x($from, $to); $from has internal_id_key $fk; $to has internal_id_key $tk; $fk == $tk; delete $x;`
      );
      wTx.tx.query(`match $r isa owned_by; delete;`);
    });
    logger.info(`[MIGRATION] reindex > Delete orphan stix_relation`);
    await executeWrite((wTx) => {
      wTx.tx.query(`match $r isa stix_relation; not {$r ($x, $y) isa stix_relation;}; delete;`);
    });
    logger.info(`[MIGRATION] reindex > Delete orphan stix_relation_embedded`);
    await executeWrite((wTx) => {
      wTx.tx.query(`match $r isa stix_relation_embedded; not {$r ($x, $y) isa stix_relation_embedded;}; delete;`);
    });
  } catch (err) {
    logger.info(`[MIGRATION] reindex > Error during deleting orphan relations, try to index...`, { error: err });
  }
  try {
    await internalDirectWrite('undefine UsageIndicatesRule sub rule;');
  } catch (err) {
    logger.info('[MIGRATION] reindex > Undefine the rule (not exists)');
  }
  await index();
  logger.info(`[MIGRATION] reindex > Migration complete`);
  next();
};

export const down = async (next) => {
  next();
};
