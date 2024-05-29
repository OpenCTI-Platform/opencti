import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'TAXIIAPI_SETCSVMAPPERS',
    description: 'Manage CSV mappers',
    attribute_order: 2520
  });
  next();
};

export const down = async (next) => {
  next();
};
