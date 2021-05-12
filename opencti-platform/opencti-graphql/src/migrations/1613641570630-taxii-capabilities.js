import { createCapabilities, TAXII_CAPABILITIES } from '../initialization';
import { deleteElementById, loadById } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';
import { generateStandardId } from '../schema/identifier';
import { SYSTEM_USER } from '../schema/general';

export const up = async (next) => {
  // Create taxii capabilities
  await createCapabilities([TAXII_CAPABILITIES]);
  // Delete old inference capability
  const inferenceCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'SETTINGS_SETINFERENCES' });
  const element = await loadById(SYSTEM_USER, inferenceCapabilityId, ENTITY_TYPE_CAPABILITY);
  if (element) {
    await deleteElementById(SYSTEM_USER, inferenceCapabilityId, ENTITY_TYPE_CAPABILITY);
  }
  next();
};

export const down = async (next) => {
  next();
};
