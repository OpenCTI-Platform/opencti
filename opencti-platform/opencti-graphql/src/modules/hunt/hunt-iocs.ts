import { isIPv4, isIPv6 } from 'node:net';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition, BasicStoreRelation } from '../../types/store';
import { ValidationError } from '../../config/errors';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../database/cache';
import { pageEntitiesConnection, pageRegardingEntitiesConnection, topRelationsList } from '../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreSettings } from '../../types/settings';
import { RELATION_GRANTED_TO, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { RELATION_INDICATES, RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import {
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_URL,
} from '../../schema/stixCyberObservable';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { findByIds } from './hunt-loaders';
import { HUNT_IOC_CONTAINER_TYPES, HUNT_IOC_OBSERVABLE_TYPES, HUNT_IOC_SUBJECT_TYPES } from './hunt-entity-types';
import { type BasicStoreEntityHunt, type HuntIocValue, INPUT_HUNT_SOURCES, RELATION_HUNT_SOURCES } from './hunt-types';
import { HUNT_CONFIG, parseHuntFilterGroup, sha256 } from './hunt-utils';

export const HUNT_IOC_HASH_ALGORITHMS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'] as const;
const HASH_ALGORITHM_BY_LENGTH: Record<number, string> = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' };
const IOC_VALUE_MAX_LENGTH = 2048;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$/;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[a-z0-9.-]{1,253}$/;
const MAC_PATTERN = /^[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}$/;
const HEX_PATTERN = /^[0-9a-f]+$/;
const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;
// One `<object>:<path> = '<value>'` comparison of a STIX pattern
const STIX_COMPARISON = /([a-z0-9-]+):([a-z0-9_]+(?:\.(?:'[^']+'|[a-z0-9_-]+))*)\s*=\s*'((?:[^'\\]|\\.)*)'/gi;
const STIX_VALUE_OBJECTS: Record<string, string> = {
  'ipv4-addr': ENTITY_IPV4_ADDR,
  'ipv6-addr': ENTITY_IPV6_ADDR,
  'domain-name': ENTITY_DOMAIN_NAME,
  hostname: ENTITY_HOSTNAME,
  'x-opencti-hostname': ENTITY_HOSTNAME,
  url: ENTITY_URL,
  'email-addr': ENTITY_EMAIL_ADDR,
  'mac-addr': ENTITY_MAC_ADDR,
};

export interface HuntIocSource {
  id: string;
  standard_id: string;
  entity_type: string;
  name: string;
}

/** One value an indicator hunt looks up, with the indicators and observables it comes from (none for a pasted value). */
export interface HuntIoc {
  key: string;
  observable_type: string;
  hash_algorithm: string | null;
  value: string;
  sources: HuntIocSource[];
}

export interface HuntIocSet {
  iocs: HuntIoc[];
  /** Indicators and observables left out: more restricted than the hunt, a run would disclose them to its readers */
  restricted_count: number;
  /** Indicators without a value a lookup can search (pattern of another language, no equality comparison) */
  unsupported_count: number;
  /** More values than a run looks up */
  truncated: boolean;
}

interface IocValue {
  observable_type: string;
  hash_algorithm: string | null;
  value: string;
}

const hashAlgorithmOf = (rawAlgorithm: string): string | null => {
  const compact = rawAlgorithm.replace(/['"]/g, '').replace(/[-_\s]/g, '').toUpperCase();
  switch (compact) {
    case 'MD5': return 'MD5';
    case 'SHA1': return 'SHA-1';
    case 'SHA256': return 'SHA-256';
    case 'SHA512': return 'SHA-512';
    default: return null;
  }
};

/**
 * The value of an observable as platforms store it, null when it is not a valid value of its type: addresses, domains
 * and hashes are compared case-insensitively, a URL keeps its case.
 */
export const normalizeIocValue = (observableType: string, rawValue: string, hashAlgorithm?: string | null): IocValue | null => {
  const trimmed = (rawValue ?? '').trim();
  if (trimmed.length === 0 || trimmed.length > IOC_VALUE_MAX_LENGTH) {
    return null;
  }
  const lower = trimmed.toLowerCase();
  switch (observableType) {
    case ENTITY_IPV4_ADDR:
      return isIPv4(trimmed) ? { observable_type: observableType, hash_algorithm: null, value: trimmed } : null;
    case ENTITY_IPV6_ADDR:
      return isIPv6(trimmed) ? { observable_type: observableType, hash_algorithm: null, value: lower } : null;
    case ENTITY_DOMAIN_NAME: {
      const domain = lower.replace(/\.$/, '');
      return DOMAIN_PATTERN.test(domain) ? { observable_type: observableType, hash_algorithm: null, value: domain } : null;
    }
    case ENTITY_HOSTNAME: {
      const hostname = lower.replace(/\.$/, '');
      return HOSTNAME_PATTERN.test(hostname) ? { observable_type: observableType, hash_algorithm: null, value: hostname } : null;
    }
    case ENTITY_URL:
      return URL_PATTERN.test(trimmed) ? { observable_type: observableType, hash_algorithm: null, value: trimmed } : null;
    case ENTITY_EMAIL_ADDR:
      return EMAIL_PATTERN.test(lower) ? { observable_type: observableType, hash_algorithm: null, value: lower } : null;
    case ENTITY_MAC_ADDR:
      return MAC_PATTERN.test(lower) ? { observable_type: observableType, hash_algorithm: null, value: lower.replace(/-/g, ':') } : null;
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE: {
      if (!HEX_PATTERN.test(lower)) {
        return null;
      }
      const byLength = HASH_ALGORITHM_BY_LENGTH[lower.length] ?? null;
      const algorithm = hashAlgorithm ? hashAlgorithmOf(hashAlgorithm) : byLength;
      return algorithm && algorithm === byLength ? { observable_type: observableType, hash_algorithm: algorithm, value: lower } : null;
    }
    default:
      return null;
  }
};

/** The observable type of a pasted value, null when it is none an indicator hunt looks up. */
export const detectIocType = (rawValue: string): string | null => {
  const value = (rawValue ?? '').trim();
  const candidates = [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL, ENTITY_EMAIL_ADDR, ENTITY_MAC_ADDR, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_DOMAIN_NAME];
  return candidates.find((type) => normalizeIocValue(type, value) !== null) ?? null;
};

/** The values of the equality comparisons of a STIX pattern a lookup can search. */
export const extractStixPatternValues = (pattern: string): IocValue[] => {
  const values: IocValue[] = [];
  for (const match of (pattern ?? '').matchAll(STIX_COMPARISON)) {
    const objectType = match[1].toLowerCase();
    const path = match[2];
    const value = match[3].replace(/\\(['\\])/g, '$1');
    let normalized: IocValue | null = null;
    if (objectType === 'file' && path.toLowerCase().startsWith('hashes.')) {
      normalized = normalizeIocValue(ENTITY_HASHED_OBSERVABLE_STIX_FILE, value, path.substring('hashes.'.length));
    } else if (STIX_VALUE_OBJECTS[objectType] && path.toLowerCase() === 'value') {
      normalized = normalizeIocValue(STIX_VALUE_OBJECTS[objectType], value);
    }
    if (normalized) {
      values.push(normalized);
    }
  }
  return values;
};

export type IocElement = BasicStoreEntity & Record<string, any>;

/** The values an indicator or an observable brings to an indicator hunt. */
export const iocValuesOfElement = (element: IocElement): IocValue[] => {
  if (element.entity_type === ENTITY_TYPE_INDICATOR) {
    return element.pattern_type === 'stix' && typeof element.pattern === 'string' ? extractStixPatternValues(element.pattern) : [];
  }
  if (element.entity_type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    const hashes = (element.hashes ?? {}) as Record<string, string>;
    return Object.entries(hashes).flatMap(([algorithm, hash]) => {
      const normalized = typeof hash === 'string' ? normalizeIocValue(ENTITY_HASHED_OBSERVABLE_STIX_FILE, hash, algorithm) : null;
      return normalized ? [normalized] : [];
    });
  }
  if (HUNT_IOC_OBSERVABLE_TYPES.includes(element.entity_type) && typeof element.value === 'string') {
    const normalized = normalizeIocValue(element.entity_type, element.value);
    return normalized ? [normalized] : [];
  }
  return [];
};

export const iocKey = (value: IocValue) => sha256(`${value.observable_type}|${value.hash_algorithm ?? ''}|${value.value}`).substring(0, 24);

const parseIocValueItem = (rawItem: unknown, index: number): Partial<HuntIocValue> => {
  if (typeof rawItem !== 'string') {
    return rawItem as Partial<HuntIocValue>;
  }
  try {
    return JSON.parse(rawItem) as Partial<HuntIocValue>;
  } catch {
    throw ValidationError(`Pasted value ${index + 1} must be a JSON object with an observable type and a value`, 'hunt_ioc_values');
  }
};

/**
 * Normalizes the values pasted in an indicator hunt; refuses a value that is not a valid value of its type, deduplicates
 * the others.
 */
export const normalizeHuntIocValues = (rawValues: unknown): HuntIocValue[] => {
  if (rawValues === null || rawValues === undefined || rawValues === '') {
    return [];
  }
  const items = Array.isArray(rawValues) ? rawValues : [rawValues];
  if (items.length > HUNT_CONFIG.maxIocsPerRun) {
    throw ValidationError(`An indicator hunt looks for at most ${HUNT_CONFIG.maxIocsPerRun} pasted values`, 'hunt_ioc_values');
  }
  const byKey = new Map<string, HuntIocValue>();
  items.forEach((rawItem, index) => {
    const item = parseIocValueItem(rawItem, index);
    const observableType = typeof item?.observable_type === 'string' ? item.observable_type : '';
    const normalized = HUNT_IOC_OBSERVABLE_TYPES.includes(observableType) ? normalizeIocValue(observableType, String(item.value ?? '')) : null;
    if (!normalized) {
      throw ValidationError(`Pasted value ${index + 1} is not a valid ${observableType || 'observable'}: ${String(item?.value ?? '').substring(0, 120)}`, 'hunt_ioc_values');
    }
    byKey.set(iocKey(normalized), { observable_type: normalized.observable_type, value: normalized.value });
  });
  return Array.from(byKey.values());
};

/**
 * Whether every reader of a hunt can read an indicator or an observable, so that a run of the hunt never discloses it:
 * each of its markings is matched by a marking of the hunt of the same type and at least the same level, and it is
 * shared with every organization the hunt is shared with. With a platform organization, the readers of an element are
 * the platform organization and the organizations it is shared with: an element shared with none is readable by the
 * platform organization only, so a hunt shared with an organization never discloses it.
 */
type AccessRestricted = { [RELATION_OBJECT_MARKING]?: string[]; [RELATION_GRANTED_TO]?: string[] };

export const isDisclosableByHunt = (hunt: AccessRestricted, element: AccessRestricted, markings: Map<string, BasicStoreEntityMarkingDefinition>) => {
  const huntMarkings = (hunt[RELATION_OBJECT_MARKING] ?? []).map((id) => markings.get(id)).filter((marking) => !!marking);
  const covered = (element[RELATION_OBJECT_MARKING] ?? []).every((id) => {
    const marking = markings.get(id);
    return !!marking && huntMarkings.some((huntMarking) => huntMarking.definition_type === marking.definition_type
      && huntMarking.x_opencti_order >= marking.x_opencti_order);
  });
  if (!covered) {
    return false;
  }
  const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];
  const huntOrganizations = hunt[RELATION_GRANTED_TO] ?? [];
  return huntOrganizations.every((id) => elementOrganizations.includes(id));
};

/**
 * Whether every reader of an object can read an element, by the markings of both and, with a platform organization,
 * their organizations: without one, organizations do not restrict reading.
 */
export const isReadableByReadersOf = async (context: AuthContext, holder: AccessRestricted, element: AccessRestricted) => {
  const [settings, markings] = await Promise.all([
    getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS),
    getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
  ]);
  const restrictions = settings.platform_organization ? holder : { ...holder, [RELATION_GRANTED_TO]: [] };
  return isDisclosableByHunt(restrictions, element, markings as Map<string, BasicStoreEntityMarkingDefinition>);
};

export const IOC_ELEMENT_TYPES = [ENTITY_TYPE_INDICATOR, ...HUNT_IOC_OBSERVABLE_TYPES];

/** Indicators and observables contained in a report, a grouping or an incident response. */
export const listContainedIocElements = async (context: AuthContext, user: AuthUser, sourceId: string, first: number) => {
  const connection = await pageRegardingEntitiesConnection<IocElement>(context, user, sourceId, RELATION_OBJECT, IOC_ELEMENT_TYPES, false, { first });
  return connection.edges.map((edge) => edge.node);
};

/**
 * The other side of the relationships of a type from or to an element, read through the relationships: the target side
 * of `indicates` and of `related-to` from an observable is not indexed on the target, so the target cannot list them.
 */
export const listRelatedElements = async (
  context: AuthContext,
  user: AuthUser,
  relationType: string,
  side: { fromId: string } | { toId: string },
  types: string[],
  first: number,
) => {
  const isFrom = 'fromId' in side;
  const relations = await topRelationsList<any>(context, user, relationType, {
    ...side,
    ...(isFrom ? { toTypes: types } : { fromTypes: types }),
    first,
  }) as BasicStoreRelation[];
  const ids = Array.from(new Set(relations.map((relation) => (isFrom ? relation.toId : relation.fromId))));
  return findByIds<IocElement>(context, user, ids, { type: types });
};

/** Indicators indicating a threat or an incident, and observables related to it. */
export const listSubjectIocElements = async (context: AuthContext, user: AuthUser, subjectId: string, first: number) => {
  const [indicators, observables] = await Promise.all([
    listRelatedElements(context, user, RELATION_INDICATES, { toId: subjectId }, [ENTITY_TYPE_INDICATOR], first),
    listRelatedElements(context, user, RELATION_RELATED_TO, { toId: subjectId }, HUNT_IOC_OBSERVABLE_TYPES, first),
  ]);
  return [...indicators, ...observables];
};

/** The name an indicator or an observable is shown with. */
export const iocElementName = (element: IocElement) => String(element.name ?? element.value ?? element.observable_value ?? element.standard_id);

/**
 * The values an indicator hunt looks up: its indicators and observables, the indicators and observables contained in
 * its reports, groupings and incident responses or linked to its threats and incidents, those matching its filter, and
 * its pasted values. Read again at every run, so that a hunt follows the intelligence it is based on. The sources, the
 * expansions and the filter share one budget of elements read, one more than a run looks up, a query that reads
 * nothing taking one: however many sources a hunt has, resolving its values reads and queries a bounded number of
 * elements, and the sources and values left unread make the set truncated.
 */
export const resolveHuntIocSet = async (context: AuthContext, hunt: BasicStoreEntityHunt): Promise<HuntIocSet> => {
  const max = HUNT_CONFIG.maxIocsPerRun;
  let budget = max + 1;
  const sourceIds = hunt[RELATION_HUNT_SOURCES] ?? [];
  const readSourceIds = sourceIds.slice(0, budget);
  const sources = await findByIds<IocElement>(context, SYSTEM_USER, readSourceIds);
  const elements: IocElement[] = sources.filter((source) => IOC_ELEMENT_TYPES.includes(source.entity_type));
  budget -= elements.length;
  const expansions = sources.filter((source) => HUNT_IOC_CONTAINER_TYPES.includes(source.entity_type) || HUNT_IOC_SUBJECT_TYPES.includes(source.entity_type));
  for (let index = 0; index < expansions.length && budget > 0; index += 1) {
    const source = expansions[index];
    // Expanded elements of revoked indicators are not hunted, an explicitly chosen one is
    const expanded = HUNT_IOC_CONTAINER_TYPES.includes(source.entity_type)
      ? await listContainedIocElements(context, SYSTEM_USER, source.internal_id, budget)
      : (await listSubjectIocElements(context, SYSTEM_USER, source.internal_id, budget)).slice(0, budget);
    budget -= Math.max(1, expanded.length);
    elements.push(...expanded.filter((element) => element.revoked !== true));
  }
  const filters = parseHuntFilterGroup(hunt.hunt_ioc_filters, 'hunt_ioc_filters');
  if (filters && budget > 0) {
    const matching = await pageEntitiesConnection<IocElement>(context, SYSTEM_USER, IOC_ELEMENT_TYPES, { filters, first: budget });
    budget -= Math.max(1, matching.edges.length);
    elements.push(...matching.edges.map((edge) => edge.node));
  }
  // A spent budget read more elements than a run looks up, or left sources and the filter unread
  const truncated = budget <= 0 || readSourceIds.length < sourceIds.length;
  const markings = await getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const byKey = new Map<string, HuntIoc>();
  const seen = new Set<string>();
  let restricted = 0;
  let unsupported = 0;
  elements.forEach((element) => {
    if (seen.has(element.internal_id)) {
      return;
    }
    seen.add(element.internal_id);
    if (!isDisclosableByHunt(hunt, element, markings as Map<string, BasicStoreEntityMarkingDefinition>)) {
      restricted += 1;
      return;
    }
    const values = iocValuesOfElement(element);
    if (values.length === 0) {
      unsupported += 1;
      return;
    }
    const source: HuntIocSource = {
      id: element.internal_id,
      standard_id: element.standard_id,
      entity_type: element.entity_type,
      name: iocElementName(element),
    };
    values.forEach((value) => {
      const key = iocKey(value);
      const existing = byKey.get(key);
      if (existing) {
        existing.sources.push(source);
      } else {
        byKey.set(key, { key, ...value, sources: [source] });
      }
    });
  });
  (hunt.hunt_ioc_values ?? []).forEach((pasted) => {
    const normalized = normalizeIocValue(pasted.observable_type, pasted.value);
    if (normalized && !byKey.has(iocKey(normalized))) {
      byKey.set(iocKey(normalized), { key: iocKey(normalized), ...normalized, sources: [] });
    }
  });
  const iocs = Array.from(byKey.values());
  return {
    iocs: iocs.slice(0, max),
    restricted_count: restricted,
    unsupported_count: unsupported,
    truncated: truncated || iocs.length > max,
  };
};

/**
 * Whether an indicator hunt has something to look for, as stored or as edited (its values are resolved at every run):
 * pasted values, a filter, or indicators, observables and entities to take them from.
 */
export const hasHuntIocLogic = (hunt: { hunt_ioc_filters?: string | null; hunt_ioc_values?: unknown; [RELATION_HUNT_SOURCES]?: unknown; [INPUT_HUNT_SOURCES]?: unknown }) => {
  const count = (value: unknown) => (Array.isArray(value) ? value.length : 0);
  return count(hunt.hunt_ioc_values) > 0
    || count(hunt[RELATION_HUNT_SOURCES]) > 0
    || count(hunt[INPUT_HUNT_SOURCES]) > 0
    || (typeof hunt.hunt_ioc_filters === 'string' && parseHuntFilterGroup(hunt.hunt_ioc_filters, 'hunt_ioc_filters') !== null);
};
