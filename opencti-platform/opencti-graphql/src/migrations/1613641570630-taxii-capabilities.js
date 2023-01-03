import { createCapabilities, TAXII_CAPABILITIES } from '../initialization';
import { deleteElementById } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';
import { generateStandardId } from '../schema/identifier';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { storeLoadById } from '../database/middleware-loader';

export const up = async (next) => {
  const context = executionContext('migration');
  // Create taxii capabilities
  await createCapabilities(context, [TAXII_CAPABILITIES]);
  // Delete old inference capability
  const inferenceCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'SETTINGS_SETINFERENCES' });
  const element = await storeLoadById(context, SYSTEM_USER, inferenceCapabilityId, ENTITY_TYPE_CAPABILITY);
  if (element) {
    await deleteElementById(context, SYSTEM_USER, inferenceCapabilityId, ENTITY_TYPE_CAPABILITY);
  }
  next();
};

export const down = async (next) => {
  next();
};
