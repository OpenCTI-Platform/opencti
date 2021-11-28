import { createCapabilities } from '../initialization';

export const up = async (next) => {
  // Create labels capabilities
  await createCapabilities([
    {
      name: 'BYPASSREFERENCE',
      attribute_order: 6000,
      description: 'Bypass mandatory references if any',
    },
  ]);
  next();
};

export const down = async (next) => {
  next();
};
