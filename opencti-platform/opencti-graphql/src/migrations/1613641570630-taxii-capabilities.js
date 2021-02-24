import { createCapabilities, TAXII_CAPABILITIES } from '../initialization';
import { deleteElementById } from '../database/middleware';
import { SYSTEM_USER } from '../domain/user';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';
import { generateStandardId } from '../schema/identifier';

export const up = async (next) => {
  // Create taxii capabilities
  await createCapabilities([TAXII_CAPABILITIES]);
  // Delete old inference capability
  const inferenceCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'SETTINGS_SETINFERENCES' });
  await deleteElementById(SYSTEM_USER, inferenceCapabilityId, ENTITY_TYPE_CAPABILITY);
  next();
};

export const down = async (next) => {
  next();
};
