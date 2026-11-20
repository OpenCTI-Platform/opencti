import type { AuthContext, AuthUser } from '../../../../types/user';
import { logApp } from '../../../../config/conf';
import { fetchOpenAevObjects, getOpenAevUrl, isOpenAevConnected, type OpenAevObjectPath } from '../openaev/openaev-client';
import { fetchOpenCrqObjects, getOpenCrqUrl, isOpenCrqConnected, type OpenCrqLookupKind } from '../opencrq/opencrq-client';
import { CounterpartLookupError, type CounterpartCaller } from './counterpart-errors';
import { counterpartKeysOf, type CounterpartSource } from './counterpart-keys';

export { CounterpartLookupError };
export type { CounterpartCaller };

// Same keys and normalisation as OpenAEV's CounterpartKind, so both sides cache the same entry.
export type CounterpartKind = 'ASSET' | 'ATTACK_PATTERN' | 'VULNERABILITY' | 'THREAT' | 'ALERT';

// Whether another XTM product is connected to this platform. Never carries a credential (C9: no URL either).
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
 * The answer for one OpenCTI object and one connected product (Q2.1):
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
 * A connected XTM product able to resolve counterparts. Each lookup runs as the calling user
 * (a short-lived JWT signed by this platform, as for XTM One): the product applies that user's
 * own rights, so a user without rights there gets no facts. A third product registers one more
 * provider, nothing else changes.
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
  resolve: async (kind, keys, caller) => {
    const objects = await fetchOpenAevObjects(OPENAEV_PATHS[kind], keys, caller);
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
        facts: sanitiseFacts(o.object_facts),
      }));
  },
};

const OPENCRQ_KINDS: ReadonlySet<CounterpartKind> = new Set<OpenCrqLookupKind>(['THREAT', 'VULNERABILITY', 'ASSET']);

export const openCrqProvider: CounterpartProvider = {
  product: 'opencrq',
  url: getOpenCrqUrl,
  isConnected: isOpenCrqConnected,
  supports: (kind) => OPENCRQ_KINDS.has(kind),
  resolve: async (kind, keys, caller) => {
    const objects = await fetchOpenCrqObjects(kind as OpenCrqLookupKind, keys, caller);
    const asked = new Set(keys);
    return objects
      .filter((o) => o && typeof o.object_id === 'string' && typeof o.object_url === 'string')
      // OpenCRQ answers keys in its own case (STIX ids and hostnames lower, CVEs upper): normalise them back.
      .map((o) => ({ ...o, key: normaliseCounterpartKey(kind, o.object_key) ?? o.object_key }))
      .filter((o) => asked.has(o.key))
      .map((o) => ({
        key: o.key,
        product: 'opencrq',
        object_id: o.object_id,
        object_type: o.object_type,
        object_name: o.object_name ?? null,
        object_url: o.object_url,
        facts: sanitiseFacts(o.object_facts),
      }));
  },
};

const PROVIDERS: CounterpartProvider[] = [openAevProvider, openCrqProvider];

// Short-TTL cache of found counterparts and known misses, per USER, product, kind and key: each
// product answers under the caller's own rights, so one user's answer is never served to another.
// An unavailable answer is never cached (C10).
interface CacheEntry { at: number; value: XtmCounterpart | null }
const cache = new Map<string, CacheEntry>();
const cacheKey = (userId: string, product: string, kind: CounterpartKind, key: string) => `${userId}|${product}|${kind}|${key}`;

// A product route that answered 404 does not exist on that product version: remembered per
// product and kind (the route) for the process lifetime, with one warning per product and route.
const unsupportedRoutes = new Set<string>();
const routeKey = (product: string, kind: CounterpartKind) => `${product}|${kind}`;

export const resetCounterpartCache = () => {
  cache.clear();
  unsupportedRoutes.clear();
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
  if (!provider.supports(kind) || unsupportedRoutes.has(routeKey(provider.product, kind))) {
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
      if (!unsupportedRoutes.has(route)) {
        unsupportedRoutes.add(route);
        logApp.warn('[XTM] Counterpart route not supported by the connected product', { product: provider.product, kind });
      }
    }
    missing.forEach((key) => answers.set(key, { status: reason }));
  }
  return answers;
};

/**
 * The counterparts of OpenCTI objects given by id, in every connected product (Q2.1, Q2.2):
 * the keys are read on the server from the objects the caller can read; an id the caller cannot
 * read, or whose object carries no valid key, gets no entry at all. One entry per (id, product)
 * for each connected product; a product that is not connected gets none (xtmConnections says so).
 */
export const resolveCounterpartsOfSources = async (
  sources: CounterpartSource[],
  caller: CounterpartCaller,
  providers: CounterpartProvider[] = PROVIDERS,
  now: () => number = Date.now,
): Promise<XtmCounterpartResult[]> => {
  const byKind = new Map<CounterpartKind, Set<string>>();
  for (const source of sources) {
    const set = byKind.get(source.kind) ?? new Set<string>();
    source.keys.forEach((key) => set.add(key));
    byKind.set(source.kind, set);
  }
  const results: XtmCounterpartResult[] = [];
  for (const provider of providers) {
    if (!provider.isConnected()) {
      continue;
    }
    const answersByKind = new Map<CounterpartKind, Map<string, KeyAnswer>>();
    // One call per kind and product, whatever the number of objects: a failure on one kind
    // never hides the answers of the others.
    await Promise.all([...byKind.entries()].map(async ([kind, keys]) => {
      answersByKind.set(kind, await resolveKeys(provider, kind, [...keys].slice(0, MAX_COUNTERPART_KEYS), caller, now));
    }));
    for (const source of sources) {
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
      results.push({
        id: source.id,
        product: provider.product,
        status,
        counterpart: found && found.status === 'found' ? found.counterpart : null,
      });
    }
  }
  return results;
};

export const xtmConnections = (providers: CounterpartProvider[] = PROVIDERS): XtmConnection[] => {
  return providers.map((p) => ({ product: p.product, connected: p.isConnected() }));
};

const callerOf = (user: AuthUser): CounterpartCaller => ({ id: user.id, user_email: user.user_email });

export const findXtmConnections = async (_context: AuthContext, _user: AuthUser) => xtmConnections();

export const findXtmCounterpartsByIds = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const connected = PROVIDERS.some((p) => p.isConnected());
  if (!connected || ids.length === 0) {
    return [];
  }
  const sources = await counterpartKeysOf(context, user, ids.slice(0, MAX_COUNTERPART_IDS), normaliseCounterpartKey);
  return resolveCounterpartsOfSources(sources, callerOf(user));
};
