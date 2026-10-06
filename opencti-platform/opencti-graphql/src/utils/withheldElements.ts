import type { AuthContext, AuthUser } from '../types/user';
import type { FilterGroup } from '../generated/graphql';
import type { BasicStoreBase } from '../types/store';
import { addFilter } from './filtering/filtering-utils';

/**
 * Elements a module withholds from readers until it could restrict or delete them, whatever their own access rules
 * still allow: a provider gives, for a reader, the internal ids of the elements of one entity type withheld from them.
 */
export type WithheldElementsProvider = (context: AuthContext, user: AuthUser) => Promise<string[]>;

/**
 * Elements withheld from a reader for a reason only each element gives, too costly to list for every element of the
 * type: a check gives, among the internal ids of elements of one entity type a load by id found or a listing may show,
 * those withheld from the reader.
 */
export type WithheldElementsCheck = (context: AuthContext, user: AuthUser, ids: string[]) => Promise<string[]>;

/**
 * The internal ids of the elements a listing of the type may show the reader under its filters, among those a check of
 * the type may withhold: the check reads them, and the listing leaves the withheld ones out of its query, so that its
 * pages, counts and distributions stay exact.
 */
export type WithheldListingCandidates = (context: AuthContext, user: AuthUser, filters?: FilterGroup | null) => Promise<string[]>;

const WITHHELD_ELEMENTS_PROVIDERS = new Map<string, WithheldElementsProvider[]>();
const WITHHELD_ELEMENTS_CHECKS = new Map<string, WithheldElementsCheck[]>();
const WITHHELD_LISTING_CANDIDATES = new Map<string, WithheldListingCandidates[]>();
// Read once per request, whatever the number of elements it loads or lists.
const withheldByContext = new WeakMap<AuthContext, Map<string, Promise<string[]>>>();
const checkedByContext = new WeakMap<AuthContext, Map<string, Promise<boolean>>>();
// Carried by the context a check runs with, and by every context derived from it: what a check loads to decide is not
// checked again, so that a check never runs into itself.
const IN_WITHHELD_CHECK = Symbol('withheld elements check');
type CheckedContext = AuthContext & { [IN_WITHHELD_CHECK]?: true };
const isInCheck = (context: AuthContext | undefined) => !!(context as CheckedContext | undefined)?.[IN_WITHHELD_CHECK];
// Some loads run before a module received its execution context: they read the elements withheld without a cache.
const cacheOf = <T>(caches: WeakMap<AuthContext, Map<string, T>>, context: AuthContext | undefined): Map<string, T> => {
  if (!context) return new Map<string, T>();
  const known = caches.get(context) ?? new Map<string, T>();
  caches.set(context, known);
  return known;
};

export const registerWithheldElements = (entityType: string, provider: WithheldElementsProvider) => {
  WITHHELD_ELEMENTS_PROVIDERS.set(entityType, [...(WITHHELD_ELEMENTS_PROVIDERS.get(entityType) ?? []), provider]);
};

export const registerWithheldElementsCheck = (entityType: string, check: WithheldElementsCheck, candidates: WithheldListingCandidates) => {
  WITHHELD_ELEMENTS_CHECKS.set(entityType, [...(WITHHELD_ELEMENTS_CHECKS.get(entityType) ?? []), check]);
  WITHHELD_LISTING_CANDIDATES.set(entityType, [...(WITHHELD_LISTING_CANDIDATES.get(entityType) ?? []), candidates]);
};

export const withheldElementIds = (context: AuthContext, user: AuthUser, entityType: string): Promise<string[]> => {
  const providers = WITHHELD_ELEMENTS_PROVIDERS.get(entityType) ?? [];
  if (providers.length === 0) {
    return Promise.resolve([]);
  }
  const known = cacheOf(withheldByContext, context);
  const key = `${user.id}|${entityType}`;
  const cached = known.get(key);
  if (cached) {
    return cached;
  }
  const ids = Promise.all(providers.map((provider) => provider(context, user))).then((lists) => lists.flat());
  known.set(key, ids);
  return ids;
};

// Among the ids of elements of the type, those the checks of the type withhold from the reader, each checked once per request.
const checkedWithheldIds = async (context: AuthContext, user: AuthUser, entityType: string, ids: string[]): Promise<string[]> => {
  const checks = WITHHELD_ELEMENTS_CHECKS.get(entityType) ?? [];
  if (checks.length === 0 || ids.length === 0) {
    return [];
  }
  const known = cacheOf(checkedByContext, context);
  const keyOf = (id: string) => `${user.id}|${entityType}|${id}`;
  const unchecked = ids.filter((id) => !known.has(keyOf(id)));
  if (unchecked.length > 0) {
    const checkContext: CheckedContext = { ...context, [IN_WITHHELD_CHECK]: true };
    const withheld = Promise.all(checks.map((check) => check(checkContext, user, unchecked))).then((lists) => new Set(lists.flat()));
    unchecked.forEach((id) => known.set(keyOf(id), withheld.then((set) => set.has(id))));
  }
  const flags = await Promise.all(ids.map((id) => known.get(keyOf(id))));
  return ids.filter((_, index) => flags[index]);
};

/**
 * The elements a load by id found that the reader may see: every loader, generic lookup and STIX conversion reads
 * through it. Only the elements of a type some module withholds from are checked, so other loads cost nothing.
 */
export const withoutWithheldHits = async <T extends Pick<BasicStoreBase, 'internal_id' | 'entity_type'>>(
  context: AuthContext,
  user: AuthUser,
  elements: T[],
): Promise<T[]> => {
  if (elements.length === 0 || isInCheck(context)) return elements;
  const isWithholding = (type: string) => WITHHELD_ELEMENTS_PROVIDERS.has(type) || WITHHELD_ELEMENTS_CHECKS.has(type);
  const types = [...new Set(elements.map((element) => element.entity_type))].filter(isWithholding);
  if (types.length === 0) return elements;
  const lists = await Promise.all(types.map(async (type) => {
    const ids = elements.filter((element) => element.entity_type === type).map((element) => element.internal_id);
    const [listed, checked] = await Promise.all([withheldElementIds(context, user, type), checkedWithheldIds(context, user, type, ids)]);
    return [...listed, ...checked];
  }));
  const withheld = new Set(lists.flat());
  return withheld.size === 0 ? elements : elements.filter((element) => !withheld.has(element.internal_id));
};

/**
 * Whether the element of the type with this internal id is withheld from the reader, asked without loading it: a load
 * by id answers for a withheld element as for an unknown one, so a guard that must tell them apart asks here.
 */
export const isElementWithheld = async (context: AuthContext, user: AuthUser, entityType: string, internalId: string) => {
  return (await withoutWithheldHits(context, user, [{ internal_id: internalId, entity_type: entityType }])).length === 0;
};

/** The element a loader found, or nothing when it is withheld from the reader (as a loader answers for an unknown id). */
export const unlessWithheld = async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, entityType: string, element: T): Promise<T> => {
  if (element && (await withoutWithheldHits(context, user, [{ ...element, entity_type: entityType }])).length === 0) {
    return undefined as unknown as T;
  }
  return element;
};

/**
 * The filters of a listing of the type, with the elements withheld from the reader left out: those its providers list,
 * and those its checks withhold among the candidates of the listing.
 */
export const withoutWithheldElements = async (context: AuthContext, user: AuthUser, entityType: string, filters?: FilterGroup | null) => {
  const listed = await withheldElementIds(context, user, entityType);
  const visible = listed.length > 0 ? addFilter(filters, 'internal_id', listed, 'not_eq', 'and') : filters;
  const candidatesOf = WITHHELD_LISTING_CANDIDATES.get(entityType) ?? [];
  if (candidatesOf.length === 0 || isInCheck(context)) return visible;
  const checkContext: CheckedContext = { ...context, [IN_WITHHELD_CHECK]: true };
  const candidates = [...new Set((await Promise.all(candidatesOf.map((candidatesFor) => candidatesFor(checkContext, user, visible)))).flat())];
  const checked = await checkedWithheldIds(context, user, entityType, candidates);
  return checked.length > 0 ? addFilter(visible, 'internal_id', checked, 'not_eq', 'and') : visible;
};
