import { takeWriteTx, commitWriteTx } from '../src/database/grakn';
import { logger } from '../src/config/conf';

module.exports.up = async next => {
  try {
    const wTx = await takeWriteTx();
    await wTx.tx.query('match $x isa Connector; delete $x;');
    await wTx.tx.query('undefine Connector sub entity;');
    await wTx.tx.query('match $x isa connector_identifier; delete $x;');
    await wTx.tx.query('undefine connector_identifier sub attribute;');
    await wTx.tx.query('match $x isa connector_config; delete $x;');
    await wTx.tx.query('undefine connector_config sub attribute;');
    await commitWriteTx(wTx);
  } catch (err) {
    logger.error(err);
  }
  next();
};

module.exports.down = async next => {
  next();
};