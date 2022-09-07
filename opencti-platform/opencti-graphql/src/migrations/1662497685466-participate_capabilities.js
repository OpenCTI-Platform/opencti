import { addCapability } from '../domain/grant';
import { SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const capabilityName = 'KNOWLEDGE_KNPARTICIPATE';
  await addCapability(SYSTEM_USER, { name: capabilityName, description: 'Access to collaborative creation', attribute_order: 150 });
  next();
};

export const down = async (next) => {
  next();
};
