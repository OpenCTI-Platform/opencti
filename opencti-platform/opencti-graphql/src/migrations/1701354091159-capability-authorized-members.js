import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS',
    description: 'Manage authorized members',
    attribute_order: 310
  });
  next();
};

export const down = async (next) => {
  next();
};
