import conf, { logApp } from '../../../../config/conf';
import { getHttpClient } from '../../../../utils/http-client';
import { counterpartAuthorization } from '../core/counterpart-auth';
import { type CounterpartCaller, lookupFailureOf } from '../core/counterpart-errors';

// OpenAEV's default tenant (io.openaev.database.model.Tenant.DEFAULT_TENANT_UUID): the tenant a
// single-tenant OpenAEV serves. A multi-tenant OpenAEV is reached with xtm:openaev_tenant_id.
export const OPENAEV_DEFAULT_TENANT_ID = '2cffad3a-0001-4078-b0e2-ef74274022c3';
const OPENAEV_TIMEOUT_MS = 5000;

export type OpenAevObjectPath = 'assets' | 'attack-patterns' | 'vulnerabilities' | 'threats' | 'alerts';

// One object OpenAEV holds for a key we asked for (OpenAEV LocalObjectOutput).
export interface OpenAevLocalObject {
  object_key: string;
  object_id: string;
  object_type: string;
  object_name: string | null;
  object_url: string;
  // Key facts OpenAEV computed for the object (findings, simulations); absent when the caller has no rights there.
  object_facts?: { fact_key: string; fact_value: string }[] | null;
}

const trimSlash = (url: string) => url.replace(/\/+$/, '');

export const getOpenAevUrl = (): string | null => {
  const url = conf.get('xtm:openaev_url');
  return url ? trimSlash(String(url)) : null;
};

const getOpenAevTenantId = (): string => {
  return conf.get('xtm:openaev_tenant_id') || OPENAEV_DEFAULT_TENANT_ID;
};

// The lookups run as the calling user (a JWT this platform signs): the URL is the connection.
export const isOpenAevConnected = (): boolean => !!getOpenAevUrl();

/**
 * Asks OpenAEV which of the given keys it holds (POST /api/tenants/{tenant}/xtm/objects/{kind}),
 * as the calling user: OpenAEV reads them under that user's rights, tenant scope and markings.
 * Throws CounterpartLookupError: not_supported on a 404 (an OpenAEV without the route),
 * forbidden on a 403 (the user lacks OpenAEV's SEARCH right on that kind: draws nothing for that
 * user), unavailable on anything else (a wrong tenant id answers 401 from XtmUserJwtExtractor).
 */
export const fetchOpenAevObjects = async (path: OpenAevObjectPath, keys: string[], caller: CounterpartCaller): Promise<OpenAevLocalObject[]> => {
  const url = getOpenAevUrl();
  if (!url || keys.length === 0) {
    return [];
  }
  try {
    const httpClient = getHttpClient({
      baseURL: url,
      // xtm:openaev_url is set by the platform administrator, like XTM One and XTM Hub.
      trusted: true,
      responseType: 'json',
      timeout: OPENAEV_TIMEOUT_MS,
      headers: {
        Authorization: await counterpartAuthorization(caller, url),
        'Content-Type': 'application/json',
      },
    });
    const tenantId = encodeURIComponent(getOpenAevTenantId());
    // No redirect: the user's token would follow it.
    const response = await httpClient.post(`/api/tenants/${tenantId}/xtm/objects/${path}`, { counterpart_keys: keys }, { maxRedirects: 0 });
    if (!Array.isArray(response.data)) {
      throw Object.assign(new Error('unreadable body'), { status: 'unreadable' });
    }
    return response.data as OpenAevLocalObject[];
  } catch (error: any) {
    throw lookupFailureOf(error, 'OpenAEV', (message, meta) => logApp.warn(message, { path, ...meta }));
  }
};
