import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';
import { generateStandardId } from '../schema/identifier';
import { SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const labelsCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'SETTINGS_SETLABELS' });
  await patchAttribute(SYSTEM_USER, labelsCapabilityId, ENTITY_TYPE_CAPABILITY, { description: 'Manage labels and attributes such as report_types, malware_types, etc.' });
  next();
};

export const down = async (next) => {
  next();
};
