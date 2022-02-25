import * as R from 'ramda';
import type { Request } from 'express';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { baseUrl, basePath } from '../config/conf';

export const BYPASS = 'BYPASS';
export const BYPASS_REFERENCE = 'BYPASSREFERENCE';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

export const getBaseUrl = (req: Request): string => {
  if (baseUrl) {
    return baseUrl;
  }
  if (req) {
    const [, port] = req.headers.host ? req.headers.host.split(':') : [];
    const isCustomPort = port !== '80' && port !== '443';
    const httpPort = isCustomPort ? `:${port}` : '';
    return `${req.protocol}://${req.hostname}${httpPort}${basePath}`;
  }
  return basePath;
};

export const filterElementsAccordingToUser = (
  user: AuthUser,
  elements: Array<StixCoreObject>
): Array<StixCoreObject> => {
  const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
  // If user have bypass, grant access to all
  if (isBypassUser(user)) {
    return elements;
  }
  // If not filter by the inner markings
  return elements.filter((e) => (e.object_marking_refs ?? []).every((m) => authorizedMarkings.includes(m)));
};

export const SYSTEM_USER: AuthUser = {
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};

export const RETENTION_MANAGER_USER: AuthUser = {
  id: RETENTION_MANAGER_USER_UUID,
  internal_id: RETENTION_MANAGER_USER_UUID,
  name: 'RETENTION MANAGER',
  user_email: 'RETENTION MANAGER',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};
