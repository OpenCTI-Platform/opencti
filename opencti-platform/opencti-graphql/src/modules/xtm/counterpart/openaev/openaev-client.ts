import conf, { logApp } from '../../../../config/conf';
import { getHttpClient } from '../../../../utils/http-client';

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
  // Key facts OpenAEV computed for the object (findings, simulations); absent on older versions.
  object_facts?: { fact_key: string; fact_value: string }[] | null;
}

const trimSlash = (url: string) => url.replace(/\/+$/, '');

export const getOpenAevUrl = (): string | null => {
  const url = conf.get('xtm:openaev_url');
  return url ? trimSlash(String(url)) : null;
};

const getOpenAevToken = (): string | null => {
  const token = conf.get('xtm:openaev_token');
  return token ? String(token) : null;
};

const getOpenAevTenantId = (): string => {
  return conf.get('xtm:openaev_tenant_id') || OPENAEV_DEFAULT_TENANT_ID;
};

// Lookups need the API token: the URL alone only feeds the product switcher.
export const isOpenAevConnected = (): boolean => !!(getOpenAevUrl() && getOpenAevToken());

/**
 * Asks OpenAEV which of the given keys it holds (POST /api/tenants/{tenant}/xtm/objects/{kind}).
 * OpenAEV reads them under the token's own rights, tenant scope and markings. Any failure answers
 * an empty list: a pivot is never worth a page error.
 */
export const fetchOpenAevObjects = async (path: OpenAevObjectPath, keys: string[]): Promise<OpenAevLocalObject[]> => {
  const url = getOpenAevUrl();
  const token = getOpenAevToken();
  if (!url || !token || keys.length === 0) {
    return [];
  }
  try {
    const httpClient = getHttpClient({
      baseURL: url,
      responseType: 'json',
      timeout: OPENAEV_TIMEOUT_MS,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });
    const tenantId = encodeURIComponent(getOpenAevTenantId());
    const response = await httpClient.post(`/api/tenants/${tenantId}/xtm/objects/${path}`, { counterpart_keys: keys });
    return Array.isArray(response.data) ? response.data as OpenAevLocalObject[] : [];
  } catch (error: any) {
    // Never log the request: its headers carry the token.
    logApp.warn('[OPENAEV] Counterpart lookup failed', { path, status: error?.status, code: error?.code });
    return [];
  }
};
