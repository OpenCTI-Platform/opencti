import { executeWrite } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async (next) => {
  try {
    await executeWrite(async (wTx) => {
      await wTx.query('match $x isa connector_identifier; delete $x;');
      await wTx.query('undefine connector_identifier sub attribute;');
      await wTx.query('match $x isa connector_config; delete $x;');
      await wTx.query('undefine connector_config sub attribute;');
    });
  } catch (err) {
    logger.info('[MIGRATION] Skipped delete Connector entity');
  }
  next();
};

export const down = async (next) => {
  next();
};
