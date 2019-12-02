import { executeWrite } from '../database/grakn';
import { index } from '../database/indexing';
import { logger } from '../config/conf';

module.exports.up = async next => {
  logger.info(`[MIGRATION] reindex > Deleting potential orphan relations, this operation could take some time...`);
  await executeWrite(wTx => {
    wTx.tx.query(
      `match $x isa related-to; $x($from, $to); $from has internal_id_key $fk; $to has internal_id_key $tk; $fk == $tk; delete $x;`
    );
    wTx.tx.query(`match $r isa owned_by; delete;`);
    wTx.tx.query(`match $r isa stix_relation; not {$r ($x, $y) isa stix_relation;}; delete;`);
    wTx.tx.query(`match $r isa stix_relation_embedded; not {$r ($x, $y) isa stix_relation_embedded;}; delete;`);
  });
  await index();
  logger.info(`[MIGRATION] reindex > Migration complete`);
  next();
};

module.exports.down = async next => {
  next();
};