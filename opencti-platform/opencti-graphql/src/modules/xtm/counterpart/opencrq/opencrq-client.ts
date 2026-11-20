import conf, { logApp } from '../../../../config/conf';
import { getHttpClient } from '../../../../utils/http-client';
import { counterpartAuthorization } from '../core/counterpart-auth';
import { type CounterpartCaller, lookupErrorOf } from '../core/counterpart-errors';

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
  // The risk OpenCRQ quantifies for the object (risk_scenarios, annual_loss, fix_value); absent when the caller has no rights there.
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

// The lookups run as the calling user (a JWT this platform signs): the URL is the connection.
export const isOpenCrqConnected = (): boolean => !!getOpenCrqUrl();

/**
 * Asks OpenCRQ which of the given keys it holds (tRPC query GET {api}/xtm.lookup?input=...), as the
 * calling user: OpenCRQ applies that user's rights, the financial facts only for a user with them.
 * Throws CounterpartLookupError: not_supported on a 404 (an OpenCRQ without the procedure),
 * unavailable on anything else.
 */
export const fetchOpenCrqObjects = async (kind: OpenCrqLookupKind, keys: string[], caller: CounterpartCaller): Promise<OpenCrqLocalObject[]> => {
  const apiUrl = getOpenCrqApiUrl();
  const url = getOpenCrqUrl();
  if (!apiUrl || !url || keys.length === 0) {
    return [];
  }
  try {
    const httpClient = getHttpClient({
      baseURL: apiUrl,
      responseType: 'json',
      timeout: OPENCRQ_TIMEOUT_MS,
      headers: {
        Authorization: await counterpartAuthorization(caller, url),
        Accept: 'application/json',
      },
    });
    const input = encodeURIComponent(JSON.stringify({ kind, keys }));
    const response = await httpClient.get(`/${OPENCRQ_LOOKUP_PROCEDURE}?input=${input}`);
    const data = response.data?.result?.data;
    if (!Array.isArray(data)) {
      throw Object.assign(new Error('unreadable body'), { status: 'unreadable' });
    }
    return data as OpenCrqLocalObject[];
  } catch (error: any) {
    // Never log the request: its headers carry the user's token.
    logApp.warn('[OPENCRQ] Counterpart lookup failed', { kind, status: error?.status, code: error?.code });
    throw lookupErrorOf(error, 'OpenCRQ');
  }
};
