import conf, { logApp } from '../../../config/conf';
import { getHttpClient } from '../../../utils/http-client';

const OPENCRQ_TIMEOUT_MS = 5000;
const OPENCRQ_LOOKUP_PROCEDURE = 'xtm.lookup';

// The kinds OpenCRQ keys its objects by (OpenCRQ XTM_LOOKUP_KINDS): threats by STIX id, CVEs, assets by hostname.
export type OpenCrqLookupKind = 'THREAT' | 'VULNERABILITY' | 'ASSET';

// One object OpenCRQ holds for a key we asked for (OpenCRQ xtm.lookup answer).
export interface OpenCrqLocalObject {
  object_key: string;
  object_id: string;
  object_type: string;
  object_name: string | null;
  object_url: string;
  // The risk OpenCRQ quantifies for the object: risk_scenarios, annual_loss, fix_value.
  object_facts?: { key: string; value: string }[] | null;
}

const trimSlash = (url: string) => url.replace(/\/+$/, '');

export const getOpenCrqUrl = (): string | null => {
  const url = conf.get('xtm:opencrq_url');
  return url ? trimSlash(String(url)) : null;
};

// The tRPC base of the OpenCRQ backend: xtm:opencrq_api_url when set, else {url}/trpc.
export const getOpenCrqApiUrl = (): string | null => {
  const apiUrl = conf.get('xtm:opencrq_api_url');
  if (apiUrl) {
    return trimSlash(String(apiUrl));
  }
  const url = getOpenCrqUrl();
  return url ? `${url}/trpc` : null;
};

const getOpenCrqToken = (): string | null => {
  const token = conf.get('xtm:opencrq_token');
  return token ? String(token) : null;
};

// Lookups need the service-account token (ogrc_...): the URL alone only feeds the product switcher.
export const isOpenCrqConnected = (): boolean => !!(getOpenCrqUrl() && getOpenCrqToken());

/**
 * Asks OpenCRQ which of the given keys it holds (tRPC query GET {api}/xtm.lookup?input=...).
 * The token is an OpenCRQ service-account token, its tenant bound on the OpenCRQ side. Any failure
 * answers an empty list: a pivot is never worth a page error.
 */
export const fetchOpenCrqObjects = async (kind: OpenCrqLookupKind, keys: string[]): Promise<OpenCrqLocalObject[]> => {
  const apiUrl = getOpenCrqApiUrl();
  const token = getOpenCrqToken();
  if (!apiUrl || !token || keys.length === 0) {
    return [];
  }
  try {
    const httpClient = getHttpClient({
      baseURL: apiUrl,
      responseType: 'json',
      timeout: OPENCRQ_TIMEOUT_MS,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });
    const input = encodeURIComponent(JSON.stringify({ kind, keys }));
    const response = await httpClient.get(`/${OPENCRQ_LOOKUP_PROCEDURE}?input=${input}`);
    const data = response.data?.result?.data;
    return Array.isArray(data) ? data as OpenCrqLocalObject[] : [];
  } catch (error: any) {
    // Never log the request: its headers carry the token.
    logApp.warn('[OPENCRQ] Counterpart lookup failed', { kind, status: error?.status, code: error?.code });
    return [];
  }
};
