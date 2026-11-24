import conf, { logApp } from '../../../../config/conf';
import { getHttpClient } from '../../../../utils/http-client';
import { counterpartAuthorization } from '../core/counterpart-auth';
import { type CounterpartCaller, lookupFailureOf } from '../core/counterpart-errors';

const XTM_ONE_TIMEOUT_MS = 5000;
// XTM One's inventory lookup (XTM-One-Platform/xtm-one#1349): the assets the given identifiers name.
export const XTM_ONE_LOOKUP_PATH = '/api/v1/organization-context/assets/lookup';
// The facts the preview shows, read from the inventory asset when it holds them.
const XTM_ONE_FACTS = ['criticality', 'category'] as const;

// One inventory asset XTM One answered for a key we asked for, as the shared counterpart shape.
export interface XtmOneLocalObject {
  object_key: string;
  object_id: string;
  object_type: string;
  object_name: string | null;
  object_url: string;
  object_facts: { key: string; value: string }[];
}

const trimSlash = (url: string) => url.replace(/\/+$/, '');

export const getXtmOneUrl = (): string | null => {
  const url = conf.get('xtm:xtm_one_url');
  return url ? trimSlash(String(url)) : null;
};

// The same connection as the rest of the XTM One integration (xtm-one-client isConfigured).
export const isXtmOneConnected = (): boolean => !!(getXtmOneUrl() && conf.get('xtm:xtm_one_token'));

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Asks XTM One which of the given asset identifiers its inventory holds
 * (POST {xtm_one_url}/api/v1/organization-context/assets/lookup { keys }), as the calling user:
 * the JWT this platform signs for that user, addressed to XTM One's identity, so XTM One answers
 * only what that user may read there. Its answer is { items: [{ key, id, name, category,
 * criticality, url, ... }] }, the key echoed as asked. XTM One's inventory holds assets only.
 * Throws CounterpartLookupError: not_supported on a 404 (an XTM One without the route),
 * unavailable on anything else.
 */
export const fetchXtmOneAssets = async (keys: string[], caller: CounterpartCaller): Promise<XtmOneLocalObject[]> => {
  const url = getXtmOneUrl();
  if (!url || keys.length === 0) {
    return [];
  }
  try {
    const httpClient = getHttpClient({
      baseURL: url,
      trusted: true,
      responseType: 'json',
      timeout: XTM_ONE_TIMEOUT_MS,
      headers: {
        Authorization: await counterpartAuthorization(caller, url),
        'Content-Type': 'application/json',
      },
    });
    // No redirect: the user's token would follow it.
    const response = await httpClient.post(XTM_ONE_LOOKUP_PATH, { keys }, { maxRedirects: 0 });
    const items = response.data?.items;
    if (!Array.isArray(items)) {
      throw Object.assign(new Error('unreadable body'), { status: 'unreadable' });
    }
    return items.filter(isRecord)
      .filter((item) => typeof item.key === 'string' && typeof item.id === 'string' && typeof item.url === 'string')
      .map((item) => ({
        object_key: item.key as string,
        object_id: item.id as string,
        object_type: 'asset',
        object_name: typeof item.name === 'string' ? item.name : null,
        object_url: item.url as string,
        object_facts: XTM_ONE_FACTS.flatMap((fact) => {
          const value = item[fact];
          return typeof value === 'string' && value !== '' ? [{ key: fact, value }] : [];
        }),
      }));
  } catch (error: any) {
    throw lookupFailureOf(error, 'XTM One', (message, meta) => logApp.warn(message, meta));
  }
};
