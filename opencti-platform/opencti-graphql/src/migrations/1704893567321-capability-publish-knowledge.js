import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'EXPLORE_EXUPDATE_PUBLISH',
    description: 'Publish exploration',
    attribute_order: 1300
  });
  next();
};

export const down = async (next) => {
  next();
};
