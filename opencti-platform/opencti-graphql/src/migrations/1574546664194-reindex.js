import { executeWrite } from '../database/grakn';
import { index } from '../database/indexing';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const query = `match $x isa related-to; $x($from, $to); $from has internal_id_key $fk; $to has internal_id_key $tk; $fk == $tk; delete $x;`;
  await executeWrite(wTx => {
    wTx.tx.query(query);
  });
  const query2 = `match $r isa relation; not {$r ($x, $y) isa relation;}; get;`;
  await executeWrite(wTx => {
    wTx.tx.query(query2);
  });
  await index();
  logger.info(`[MIGRATION] reindex > Migration complete`);
  next();
};

module.exports.down = async next => {
  next();
};
