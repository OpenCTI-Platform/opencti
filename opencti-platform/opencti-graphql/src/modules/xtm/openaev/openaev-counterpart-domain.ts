import type { AuthContext, AuthUser } from '../../../types/user';
import { fetchOpenAevObjects, getOpenAevUrl, isOpenAevConnected, type OpenAevObjectPath } from './openaev-client';

// Same keys and normalisation as OpenAEV's CounterpartKind, so both sides cache the same entry.
export type CounterpartKind = 'ASSET' | 'ATTACK_PATTERN' | 'VULNERABILITY' | 'THREAT' | 'ALERT';

export interface XtmConnection {
  product: string;
  connected: boolean;
  url: string | null;
}

export interface XtmCounterpart {
  key: string;
  product: string;
  object_id: string;
  object_type: string;
  object_name: string | null;
  object_url: string;
}

/**
 * A connected XTM product able to resolve counterparts. OpenAEV is the first; a third product
 * (OpenCRQ, wave 2) registers one more provider here, nothing else changes.
 */
export interface CounterpartProvider {
  product: string;
  url: () => string | null;
  isConnected: () => boolean;
  supports: (kind: CounterpartKind) => boolean;
  resolve: (kind: CounterpartKind, keys: string[]) => Promise<XtmCounterpart[]>;
}

export const MAX_COUNTERPART_KEYS = 200;
export const COUNTERPART_CACHE_TTL_MS = 2 * 60 * 1000;

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const MITRE_PATTERN = /^[TS]\d{4}(\.\d{3})?$|^(TA|M|G|S|C)\d{4}$/;
const STIX_ID_PATTERN = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_KEY_LENGTH = 512;
// An alert link is the URL of the alert in the security platform a collector read it from.
const MAX_ALERT_LINK_LENGTH = 2048;

const isHttpUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

/** The key as both products store it, or null when it can never match. */
export const normaliseCounterpartKey = (kind: CounterpartKind, key: string | null | undefined): string | null => {
  const trimmed = (key ?? '').trim();
  if (trimmed.length === 0 || trimmed.length > (kind === 'ALERT' ? MAX_ALERT_LINK_LENGTH : MAX_KEY_LENGTH)) {
    return null;
  }
  switch (kind) {
    case 'ASSET':
      return trimmed.toLowerCase();
    case 'ATTACK_PATTERN': {
      const upper = trimmed.toUpperCase();
      return MITRE_PATTERN.test(upper) ? upper : null;
    }
    case 'VULNERABILITY': {
      const upper = trimmed.toUpperCase();
      return CVE_PATTERN.test(upper) ? upper : null;
    }
    case 'THREAT': {
      const lower = trimmed.toLowerCase();
      return STIX_ID_PATTERN.test(lower) ? lower : null;
    }
    case 'ALERT':
      // Kept as written: OpenAEV matches the link exactly (CounterpartKind.ALERT).
      return isHttpUrl(trimmed) ? trimmed : null;
    default:
      return null;
  }
};

export const normaliseCounterpartKeys = (kind: CounterpartKind, keys: string[]): string[] => {
  const out = new Set<string>();
  for (const key of keys) {
    const normalised = normaliseCounterpartKey(kind, key);
    if (normalised) {
      out.add(normalised);
    }
    if (out.size >= MAX_COUNTERPART_KEYS) {
      break;
    }
  }
  return [...out];
};

const OPENAEV_PATHS: Record<CounterpartKind, OpenAevObjectPath> = {
  ASSET: 'assets',
  ATTACK_PATTERN: 'attack-patterns',
  VULNERABILITY: 'vulnerabilities',
  THREAT: 'threats',
  ALERT: 'alerts',
};

export const openAevProvider: CounterpartProvider = {
  product: 'openaev',
  url: getOpenAevUrl,
  isConnected: isOpenAevConnected,
  supports: (kind) => kind in OPENAEV_PATHS,
  resolve: async (kind, keys) => {
    const objects = await fetchOpenAevObjects(OPENAEV_PATHS[kind], keys);
    const asked = new Set(keys);
    return objects
      .filter((o) => o && typeof o.object_id === 'string' && typeof o.object_url === 'string')
      .map((o) => ({ ...o, key: normaliseCounterpartKey(kind, o.object_key) ?? o.object_key }))
      .filter((o) => asked.has(o.key))
      .map((o) => ({
        key: o.key,
        product: 'openaev',
        object_id: o.object_id,
        object_type: o.object_type,
        object_name: o.object_name ?? null,
        object_url: o.object_url,
      }));
  },
};

const PROVIDERS: CounterpartProvider[] = [openAevProvider];

// Short-TTL cache, per product, kind and key: a found counterpart or a known miss (null). The
// lookups use the platform's own connection token, so the answer does not depend on the reader;
// the reader's right on the OpenCTI object is checked by the resolver (KNOWLEDGE).
interface CacheEntry { at: number; value: XtmCounterpart | null }
const cache = new Map<string, CacheEntry>();
const cacheKey = (product: string, kind: CounterpartKind, key: string) => `${product}|${kind}|${key}`;

export const resetCounterpartCache = () => cache.clear();

export const resolveCounterparts = async (
  kind: CounterpartKind,
  keys: string[],
  providers: CounterpartProvider[] = PROVIDERS,
  now: () => number = Date.now,
): Promise<XtmCounterpart[]> => {
  const normalised = normaliseCounterpartKeys(kind, keys);
  if (normalised.length === 0) {
    return [];
  }
  const results: XtmCounterpart[] = [];
  for (const provider of providers) {
    if (!provider.supports(kind) || !provider.isConnected()) {
      continue;
    }
    const missing: string[] = [];
    for (const key of normalised) {
      const entry = cache.get(cacheKey(provider.product, kind, key));
      if (entry && now() - entry.at < COUNTERPART_CACHE_TTL_MS) {
        if (entry.value) {
          results.push(entry.value);
        }
      } else {
        missing.push(key);
      }
    }
    if (missing.length > 0) {
      const found = await provider.resolve(kind, missing);
      const byKey = new Map(found.map((c) => [c.key, c]));
      const at = now();
      for (const key of missing) {
        const value = byKey.get(key) ?? null;
        cache.set(cacheKey(provider.product, kind, key), { at, value });
        if (value) {
          results.push(value);
        }
      }
    }
  }
  return results;
};

export const xtmConnections = (providers: CounterpartProvider[] = PROVIDERS): XtmConnection[] => {
  return providers.map((p) => ({ product: p.product, connected: p.isConnected(), url: p.isConnected() ? p.url() : null }));
};

export const findXtmConnections = async (_context: AuthContext, _user: AuthUser) => xtmConnections();

export const findXtmCounterparts = async (_context: AuthContext, _user: AuthUser, kind: CounterpartKind, keys: string[]) => {
  return resolveCounterparts(kind, keys);
};
