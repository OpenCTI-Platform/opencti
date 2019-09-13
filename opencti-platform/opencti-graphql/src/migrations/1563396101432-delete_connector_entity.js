import {
  takeWriteTx,
  commitWriteTx,
  closeWriteTx
} from '../database/grakn';

module.exports.up = async next => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query('match $x isa Connector; delete $x;');
    await wTx.tx.query('undefine Connector sub entity;');
    await wTx.tx.query('match $x isa connector_identifier; delete $x;');
    await wTx.tx.query('undefine connector_identifier sub attribute;');
    await wTx.tx.query('match $x isa connector_config; delete $x;');
    await wTx.tx.query('undefine connector_config sub attribute;');
    await commitWriteTx(wTx);
  } catch (err) {
    closeWriteTx(wTx).catch(() => next());
  }
  next();
};

module.exports.down = async next => {
  next();
};
