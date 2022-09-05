import { addCapability } from '../domain/grant';
import { SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const capabilityName = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
  await addCapability(SYSTEM_USER, { name: capabilityName, description: 'Restrict organization access', attribute_order: 290 });
  next();
};

export const down = async (next) => {
  next();
};
