import { logApp } from '../config/conf';
import { elLoadById, elReplace } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Change delete capability description';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const deleteCapability = await elLoadById(context, SYSTEM_USER, 'capability--be60f4fc-8d91-59f6-925a-1b211a06d086');
  if (deleteCapability) {
    const deleteCapabilityPatch = { description: 'Delete / Merge knowledge' };
    await elReplace(deleteCapability._index, deleteCapability.internal_id, { doc: deleteCapabilityPatch });
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
