import conf, { logApp } from '../../../../config/conf';
import { getHttpClient } from '../../../../utils/http-client';
import { exchangeXtmOneUserToken } from '../../../../domain/xtm-auth';
import { type CounterpartCaller, lookupFailureOf } from '../core/counterpart-errors';

const OPENCRQ_TIMEOUT_MS = 5000;
const OPENCRQ_LOOKUP_PROCEDURE = 'xtm.lookup';
// A JWT XTM One signed for the calling user, addressed to OpenCRQ (OpenCRQ #29): OpenCRQ reads the facts as
// that person when it verifies and the person reaches the tenant; otherwise it answers 200 with the
// links only (no facts), never an error, so a user without rights there sees the emblem without figures.
export const XTM_USER_TOKEN_HEADER = 'X-XTM-User-Token';

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

// xtm:opencrq_url, else the deprecated xtm:opengrc_url older installs still set.
export const getOpenCrqUrl = (): string | null => {
  const url = conf.get('xtm:opencrq_url') || conf.get('xtm:opengrc_url');
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

// The OpenCRQ service-account token (xtm:opencrq_token): OpenCRQ's xtm.lookup trusts only an XTM One JWT
// or a service-account bearer, which also binds the tenant (OpenCRQ #24, #26, #28, #29). Server side only.
const getOpenCrqToken = (): string | null => {
  const token = conf.get('xtm:opencrq_token');
  return token ? String(token) : null;
};

// Connected when both the URL (getOpenCrqUrl) and the service-account token are set.
export const isOpenCrqConnected = (): boolean => !!(getOpenCrqUrl() && getOpenCrqToken());

/**
 * Asks OpenCRQ which of the given keys it holds (tRPC query GET {api}/xtm.lookup?input=...) with the
 * service-account bearer, forwarding the XTM One token of the calling user in X-XTM-User-Token: OpenCRQ
 * reads the financial facts as that person; without XTM One (no token exchange) it answers the links only.
 * The bearer is the service account, never the user: any user who can read the object here gets the
 * OpenCRQ object name and link; only the facts depend on the user's own rights in OpenCRQ.
 * Throws CounterpartLookupError: not_supported on a 404 (an OpenCRQ without the procedure),
 * unavailable on anything else, a 403 included: OpenCRQ answers 403 only when the service account or
 * its tenant is refused, never for a user, so it is a fault of the connection, not a per-user right.
 */
export const fetchOpenCrqObjects = async (kind: OpenCrqLookupKind, keys: string[], caller: CounterpartCaller): Promise<OpenCrqLocalObject[]> => {
  const apiUrl = getOpenCrqApiUrl();
  const url = getOpenCrqUrl();
  const token = getOpenCrqToken();
  if (!apiUrl || !url || !token || keys.length === 0) {
    return [];
  }
  try {
    // No XTM One, or XTM One refuses the exchange: the lookup goes without it, as before.
    const userToken = await exchangeXtmOneUserToken(caller, url);
    const httpClient = getHttpClient({
      baseURL: apiUrl,
      // xtm:opencrq_url and xtm:opencrq_api_url are set by the platform administrator.
      trusted: true,
      responseType: 'json',
      timeout: OPENCRQ_TIMEOUT_MS,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        ...(userToken ? { [XTM_USER_TOKEN_HEADER]: userToken } : {}),
      },
    });
    const input = encodeURIComponent(JSON.stringify({ kind, keys }));
    // No redirect: X-XTM-User-Token would follow it (http-client strips only the standard auth headers).
    const response = await httpClient.get(`/${OPENCRQ_LOOKUP_PROCEDURE}?input=${input}`, { maxRedirects: 0 });
    const data = response.data?.result?.data;
    if (!Array.isArray(data)) {
      throw Object.assign(new Error('unreadable body'), { status: 'unreadable' });
    }
    return data as OpenCrqLocalObject[];
  } catch (error: any) {
    throw lookupFailureOf(error, 'OpenCRQ', (message, meta) => logApp.warn(message, { kind, ...meta }), { forbiddenIsPerUser: false });
  }
};
