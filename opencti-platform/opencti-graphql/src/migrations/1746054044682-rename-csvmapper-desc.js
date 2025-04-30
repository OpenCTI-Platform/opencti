import { logApp } from '../config/conf';
import { elLoadById, elReplace } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Change CSV mapper capability description';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const CSVCapability = await elLoadById(context, SYSTEM_USER, 'capability--c3d1af09-14d2-5172-9673-200de7f7f386');
  if (CSVCapability) {
    const CSVCapabilityPatch = { description: 'Manage data mappers' };
    await elReplace(CSVCapability._index, CSVCapability.internal_id, { doc: CSVCapabilityPatch });
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
