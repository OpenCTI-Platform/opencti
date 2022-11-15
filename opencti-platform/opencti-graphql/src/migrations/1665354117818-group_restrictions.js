import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNPARTICIPATE',
    description: 'Access to collaborative creation',
    attribute_order: 150
  });
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT',
    description: 'Restrict organization access',
    attribute_order: 290
  });
  next();
};

export const down = async (next) => {
  next();
};
