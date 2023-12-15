import { elUpdateIndicesMappings } from '../database/engine';

export const up = async (next) => {
  await elUpdateIndicesMappings({
    height: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
    weight: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
  });
  next();
};

export const down = async (next) => {
  next();
};
