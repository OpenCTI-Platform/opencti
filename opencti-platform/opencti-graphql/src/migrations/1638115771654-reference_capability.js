import { createCapabilities } from '../initialization';
import { BYPASS_REFERENCE, executionContext } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  // Create labels capabilities
  await createCapabilities(context, [
    {
      name: BYPASS_REFERENCE,
      attribute_order: 6000,
      description: 'Bypass mandatory references if any',
    },
  ]);
  next();
};

export const down = async (next) => {
  next();
};
