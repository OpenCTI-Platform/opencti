import * as R from 'ramda';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';

export const BYPASS = 'BYPASS';
export const ROLE_ADMINISTRATOR = 'Administrator';
export const isBypassUser = (user) => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const filterElementsAccordingToUser = (user, elements) => {
  const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
  // If user have bypass, grant access to all
  if (isBypassUser(user)) {
    return elements;
  }
  // If not filter by the inner markings
  return elements.filter((e) => (e.object_marking_refs || []).every((m) => authorizedMarkings.includes(m)));
};

export const SYSTEM_USER = {
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};
