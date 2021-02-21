import { createCapabilities } from '../initialization';

export const up = async (next) => {
  const capabilities = [
    {
      name: 'TAXIIAPI',
      attribute_order: 2500,
      description: 'Access Taxii feed',
      dependencies: [{ name: 'SETCOLLECTIONS', description: 'Manage Taxii collections', attribute_order: 2510 }],
    },
  ];
  await createCapabilities(capabilities);
  next();
};

export const down = async (next) => {
  next();
};
