import * as R from 'ramda';
import type { Request } from 'express';
import type { Context, Span, Tracer } from '@opentelemetry/api';
import { context as telemetryContext, trace } from '@opentelemetry/api';
import { INPUT_MARKINGS, OPENCTI_SYSTEM_UUID } from '../schema/general';
import { basePath, baseUrl } from '../config/conf';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, StoreCommon } from '../types/store';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';

export const BYPASS = 'BYPASS';
export const BYPASS_REFERENCE = 'BYPASSREFERENCE';
export const KNOWLEDGE_ORGANIZATION_RESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const ROLE_ADMINISTRATOR = 'Administrator';
const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';

class TracingContext {
  ctx: Context | undefined;

  tracer: Tracer;

  constructor(tracer: Tracer) {
    this.tracer = tracer;
    this.ctx = undefined;
  }

  getCtx() {
    return this.ctx;
  }

  getTracer() {
    return this.tracer;
  }

  setCurrentCtx(span: Span) {
    this.ctx = trace.setSpan(telemetryContext.active(), span);
  }
}

export const executionContext = (source: string): AuthContext => {
  const tracer = trace.getTracer('instrumentation-opencti', '1.0.0');
  const tracing = new TracingContext(tracer);
  return { source, tracing };
};

export const SYSTEM_USER: AuthUser = {
  id: OPENCTI_SYSTEM_UUID,
  internal_id: OPENCTI_SYSTEM_UUID,
  name: 'SYSTEM',
  user_email: 'SYSTEM',
  origin: { user_id: OPENCTI_SYSTEM_UUID },
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
  all_marking: [],
};

export const RETENTION_MANAGER_USER: AuthUser = {
  id: RETENTION_MANAGER_USER_UUID,
  internal_id: RETENTION_MANAGER_USER_UUID,
  name: 'RETENTION MANAGER',
  user_email: 'RETENTION MANAGER',
  origin: { user_id: RETENTION_MANAGER_USER_UUID },
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
  all_marking: [],
};

export const INTERNAL_USERS = {
  [SYSTEM_USER.id]: SYSTEM_USER,
  [RETENTION_MANAGER_USER.id]: RETENTION_MANAGER_USER
};

export const getBaseUrl = (req: Request): string => {
  if (baseUrl) {
    return baseUrl;
  }
  if (req) {
    const [, port] = req.headers.host ? req.headers.host.split(':') : [];
    const isCustomPort = port !== '80' && port !== '443';
    const httpPort = isCustomPort && port ? `:${port}` : '';
    return `${req.protocol}://${req.hostname}${httpPort}${basePath}`;
  }
  return basePath;
};

export const isBypassUser = (user: AuthUser): boolean => {
  return R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
};

const isElementMarkingsAllowed = (elementMarkings: Array<string> | undefined, markings: Array<string>) => {
  // All markings must be included
  return (elementMarkings ?? []).every((m) => markings.includes(m));
};

export const isUserCanAccessElement = (user: AuthUser, element: StoreCommon) => {
  // If user have bypass, grant access to all
  if (isBypassUser(user)) {
    return true;
  }
  // If not filter by the inner markings
  const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
  const elementMarkingIds = element[INPUT_MARKINGS]?.map((i) => i.internal_id) ?? [];
  return isElementMarkingsAllowed(elementMarkingIds, authorizedMarkings);
};

export const filterElementsAccordingToUser = (user: AuthUser, elements: Array<BasicStoreCommon>) => {
  // If user have bypass, grant access to all
  if (isBypassUser(user)) {
    return elements;
  }
  // If not filter by the inner markings
  const authorizedMarkings = user.allowed_marking.map((a) => a.internal_id);
  return elements.filter((element) => {
    const elementMarkings = element[RELATION_OBJECT_MARKING] ?? [];
    return isElementMarkingsAllowed(elementMarkings, authorizedMarkings);
  });
};
