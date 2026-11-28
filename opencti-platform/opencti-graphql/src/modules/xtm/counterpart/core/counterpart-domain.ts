import { LRUCache } from 'lru-cache';
import type { AuthContext, AuthUser } from '../../../../types/user';
import { isFeatureEnabled, logApp, XTM_COUNTERPARTS_FEATURE_FLAG } from '../../../../config/conf';
import { CounterpartLookupError, type CounterpartCaller } from './counterpart-errors';
import { counterpartKeysOf, type CounterpartSource } from './counterpart-keys';

export { CounterpartLookupError };
export type { CounterpartCaller };

// Same keys and normalisation as OpenAEV's CounterpartKind, so both sides cache the same entry.
export type CounterpartKind = 'ASSET' | 'ATTACK_PATTERN' | 'VULNERABILITY' | 'THREAT' | 'ALERT';

// Whether another XTM product is connected to this platform. Never carries a credential.
export interface XtmConnection {
  product: string;
  connected: boolean;
}

export interface XtmCounterpart {
  key: string;
  product: string;
  object_id: string;
  object_type: string;
  object_name: string | null;
  object_url: string;
  facts: XtmCounterpartFact[];
}

export interface XtmCounterpartFact {
  key: string;
  value: string;
}

/**
 * The answer for one OpenCTI object and one connected product:
 * found (with the counterpart), not_found, not_supported (the product has no such route: draw nothing),
 * unavailable (the product could not answer this time: never cached).
 */
export type XtmCounterpartStatus = 'found' | 'not_found' | 'not_supported' | 'unavailable';

export interface XtmCounterpartResult {
  id: string;
  product: string;
  status: XtmCounterpartStatus;
  counterpart: XtmCounterpart | null;
}

const MAX_FACTS = 10;
const MAX_FACT_LENGTH = 64;
const FACT_KEY_PATTERN = /^[a-z][a-z0-9_]*$/;

/**
 * The facts a product answered, kept only when well formed and short: they are shown as is.
 * OpenAEV answers { fact_key, fact_value }, OpenCRQ { key, value }.
 */
export const sanitiseFacts = (facts: unknown): XtmCounterpartFact[] => {
  if (!Array.isArray(facts)) {
    return [];
  }
  const out: XtmCounterpartFact[] = [];
  for (const fact of facts) {
    const key = fact?.fact_key ?? fact?.key;
    const value = fact?.fact_value ?? fact?.value;
    if (typeof key === 'string' && typeof value === 'string' && FACT_KEY_PATTERN.test(key)
      && key.length <= MAX_FACT_LENGTH && value.length > 0 && value.length <= MAX_FACT_LENGTH) {
      out.push({ key, value });
    }
    if (out.length >= MAX_FACTS) {
      break;
    }
  }
  return out;
};

/**
 * A connected XTM product able to resolve counterparts. OpenAEV and XTM One run each lookup as the
 * calling user (a short-lived JWT signed by this platform): the product applies that user's own
 * rights, so a user without rights there gets nothing or no facts. OpenCRQ authenticates the lookup
 * with its service account: any user who can read the object here gets the OpenCRQ object name and
 * link, and only the facts depend on the user (the XTM One token forwarded in X-XTM-User-Token).
 * A third product registers one more provider, nothing else changes.
 * resolve throws CounterpartLookupError('not_supported') when the product has no such route
 * and CounterpartLookupError('unavailable') on any other failure.
 */
export interface CounterpartProvider {
  product: string;
  url: () => string | null;
  isConnected: () => boolean;
  supports: (kind: CounterpartKind) => boolean;
  resolve: (kind: CounterpartKind, keys: string[], caller: CounterpartCaller) => Promise<XtmCounterpart[]>;
}

export const MAX_COUNTERPART_KEYS = 200;
export const MAX_COUNTERPART_IDS = 200;
export const COUNTERPART_CACHE_TTL_MS = 2 * 60 * 1000;
// Bound of the per-user answer cache: the least recently used entries go first.
export const COUNTERPART_CACHE_MAX_ENTRIES = 50_000;

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

/**
 * The counterparts a product answered for some keys, kept only when well formed and asked for,
 * their keys normalised back (each product answers keys in its own case), their facts sanitised.
 */
export const counterpartsOfAnswer = (
  product: string,
  kind: CounterpartKind,
  keys: string[],
  objects: ReadonlyArray<{ object_key: string; object_id: string; object_type: string; object_name?: string | null; object_url: string; object_facts?: unknown }>,
): XtmCounterpart[] => {
  const asked = new Set(keys);
  return objects
    // object_url becomes an href: absolute http(s) only.
    .filter((o) => o && typeof o.object_id === 'string' && typeof o.object_url === 'string' && isHttpUrl(o.object_url))
    .map((o) => ({ ...o, key: normaliseCounterpartKey(kind, o.object_key) ?? o.object_key }))
    .filter((o) => asked.has(o.key))
    .map((o) => ({
      key: o.key,
      product,
      object_id: o.object_id,
      object_type: o.object_type,
      object_name: o.object_name ?? null,
      object_url: o.object_url,
      facts: sanitiseFacts(o.object_facts),
    }));
};

// The registry: the counterpart module descriptor registers each product's provider, defined in its own
// folder (xtmone/, openaev/, opencrq/), so core imports nothing from a product folder. The order of
// registration is the order of the answers and of xtmConnections.
const PROVIDERS: CounterpartProvider[] = [];

export const registerCounterpartProvider = (provider: CounterpartProvider) => {
  const index = PROVIDERS.findIndex((p) => p.product === provider.product);
  if (index >= 0) {
    PROVIDERS[index] = provider;
  } else {
    PROVIDERS.push(provider);
  }
};

// Short-TTL cache of found counterparts and known misses, per USER, product, kind and key: each
// product answers under the caller's own rights, so one user's answer is never served to another.
// An unavailable answer is never cached. Bounded in size and evicted at the TTL; the
// TTL is also checked on read against the injected clock.
interface CacheEntry { at: number; value: XtmCounterpart | null }
const cache = new LRUCache<string, CacheEntry>({ max: COUNTERPART_CACHE_MAX_ENTRIES, ttl: COUNTERPART_CACHE_TTL_MS });
const cacheKey = (userId: string, product: string, kind: CounterpartKind, key: string) => `${userId}|${product}|${kind}|${key}`;

// A product route that answered 404 does not exist on that product version: remembered per
// product and kind (the route) for the TTL, then asked again once (R1: the product may be upgraded
// or enable the route without OpenCTI restarting). One warning per product and route per process.
const unsupportedRoutes = new Map<string, number>();
const warnedRoutes = new Set<string>();
const routeKey = (product: string, kind: CounterpartKind) => `${product}|${kind}`;

// A route that answered 403 to one user: that user has no right to read that kind there.
// Draws nothing for that user only, for the TTL; never a warning, never another user's answer.
const forbiddenRoutes = new LRUCache<string, number>({ max: COUNTERPART_CACHE_MAX_ENTRIES, ttl: COUNTERPART_CACHE_TTL_MS });
const forbiddenKey = (userId: string, product: string, kind: CounterpartKind) => `${userId}|${product}|${kind}`;

const isFresh = (at: number | undefined, now: () => number) => at !== undefined && now() - at < COUNTERPART_CACHE_TTL_MS;

export const resetCounterpartCache = () => {
  cache.clear();
  unsupportedRoutes.clear();
  warnedRoutes.clear();
  forbiddenRoutes.clear();
};

type KeyAnswer = { status: 'found'; counterpart: XtmCounterpart } | { status: 'not_found' | 'not_supported' | 'unavailable' };

/** One product's answer for each key of one kind, under the caller's rights. */
const resolveKeys = async (
  provider: CounterpartProvider,
  kind: CounterpartKind,
  keys: string[],
  caller: CounterpartCaller,
  now: () => number,
): Promise<Map<string, KeyAnswer>> => {
  const answers = new Map<string, KeyAnswer>();
  if (
    !provider.supports(kind)
    || isFresh(unsupportedRoutes.get(routeKey(provider.product, kind)), now)
    || isFresh(forbiddenRoutes.get(forbiddenKey(caller.id, provider.product, kind)), now)
  ) {
    keys.forEach((key) => answers.set(key, { status: 'not_supported' }));
    return answers;
  }
  const missing: string[] = [];
  for (const key of keys) {
    const entry = cache.get(cacheKey(caller.id, provider.product, kind, key));
    if (entry && now() - entry.at < COUNTERPART_CACHE_TTL_MS) {
      answers.set(key, entry.value ? { status: 'found', counterpart: entry.value } : { status: 'not_found' });
    } else {
      missing.push(key);
    }
  }
  if (missing.length === 0) {
    return answers;
  }
  try {
    const found = await provider.resolve(kind, missing, caller);
    const byKey = new Map(found.map((c) => [c.key, c]));
    const at = now();
    for (const key of missing) {
      const value = byKey.get(key) ?? null;
      cache.set(cacheKey(caller.id, provider.product, kind, key), { at, value });
      answers.set(key, value ? { status: 'found', counterpart: value } : { status: 'not_found' });
    }
  } catch (error) {
    const reason = error instanceof CounterpartLookupError ? error.reason : 'unavailable';
    if (reason === 'not_supported') {
      const route = routeKey(provider.product, kind);
      unsupportedRoutes.set(route, now());
      if (!warnedRoutes.has(route)) {
        warnedRoutes.add(route);
        logApp.warn('[XTM] Counterpart route not supported by the connected product', { product: provider.product, kind });
      }
    }
    if (reason === 'forbidden') {
      forbiddenRoutes.set(forbiddenKey(caller.id, provider.product, kind), now());
    }
    // A user without rights there sees what a product without the route shows: nothing.
    const status = reason === 'forbidden' ? 'not_supported' : reason;
    missing.forEach((key) => answers.set(key, { status }));
  }
  return answers;
};

/**
 * The counterparts of OpenCTI objects given by id, in every connected product:
 * the keys are read on the server from the objects the caller can read; an id the caller cannot
 * read, or whose object carries no valid key, gets no entry at all. One entry per (id, product)
 * for each connected product; a product that is not connected gets none (xtmConnections says so).
 */
export const resolveCounterpartsOfSources = async (
  sources: CounterpartSource[],
  caller: CounterpartCaller,
  providers: ReadonlyArray<CounterpartProvider> = PROVIDERS,
  now: () => number = Date.now,
): Promise<XtmCounterpartResult[]> => {
  const byKind = new Map<CounterpartKind, Set<string>>();
  for (const source of sources) {
    const set = byKind.get(source.kind) ?? new Set<string>();
    source.keys.forEach((key) => set.add(key));
    byKind.set(source.kind, set);
  }
  // The connected products are asked in parallel: one slow product never delays the others.
  const connected = providers.filter((provider) => provider.isConnected());
  const perProvider = await Promise.all(connected.map(async (provider) => {
    const answersByKind = new Map<CounterpartKind, Map<string, KeyAnswer>>();
    // One call per kind and product, whatever the number of objects: a failure on one kind
    // never hides the answers of the others.
    await Promise.all([...byKind.entries()].map(async ([kind, keys]) => {
      answersByKind.set(kind, await resolveKeys(provider, kind, [...keys].slice(0, MAX_COUNTERPART_KEYS), caller, now));
    }));
    return sources.map((source): XtmCounterpartResult => {
      const answers = source.keys.map((key) => answersByKind.get(source.kind)?.get(key)).filter((a): a is KeyAnswer => !!a);
      const found = answers.find((a) => a.status === 'found');
      let status: XtmCounterpartStatus;
      if (found) {
        status = 'found';
      } else if (answers.some((a) => a.status === 'unavailable')) {
        status = 'unavailable';
      } else if (answers.length > 0 && answers.every((a) => a.status === 'not_supported')) {
        status = 'not_supported';
      } else {
        status = 'not_found';
      }
      return {
        id: source.id,
        product: provider.product,
        status,
        counterpart: found && found.status === 'found' ? found.counterpart : null,
      };
    });
  }));
  // Results keep the providers' order, whatever order the products answered in.
  return perProvider.flat();
};

export const xtmConnections = (providers: ReadonlyArray<CounterpartProvider> = PROVIDERS): XtmConnection[] => {
  return providers.map((p) => ({ product: p.product, connected: p.isConnected() }));
};

const callerOf = (user: AuthUser): CounterpartCaller => ({ id: user.id, user_email: user.user_email });

// Domain gate of the dedicated feature flag XTM_COUNTERPARTS (declared in config/conf, off by default):
// while it is off the platform answers no connection and sends no counterpart call to another product.
export const findXtmConnections = async (_context: AuthContext, _user: AuthUser) => (
  isFeatureEnabled(XTM_COUNTERPARTS_FEATURE_FLAG) ? xtmConnections() : []
);

export const findXtmCounterpartsByIds = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  if (!isFeatureEnabled(XTM_COUNTERPARTS_FEATURE_FLAG)) {
    return [];
  }
  const connected = PROVIDERS.some((p) => p.isConnected());
  if (!connected || ids.length === 0) {
    return [];
  }
  const sources = await counterpartKeysOf(context, user, ids.slice(0, MAX_COUNTERPART_IDS), normaliseCounterpartKey);
  return resolveCounterpartsOfSources(sources, callerOf(user));
};
