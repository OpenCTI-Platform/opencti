import type { AuthContext, AuthUser } from '../types/user';
import type { FilterGroup } from '../generated/graphql';
import type { BasicStoreBase } from '../types/store';
import { addFilter } from './filtering/filtering-utils';

/**
 * Elements a module withholds from readers until it could restrict or delete them, whatever their own access rules
 * still allow: a provider gives, for a reader, the internal ids of the elements of one entity type withheld from them.
 */
export type WithheldElementsProvider = (context: AuthContext, user: AuthUser) => Promise<string[]>;

const WITHHELD_ELEMENTS_PROVIDERS = new Map<string, WithheldElementsProvider[]>();
// Read once per request, whatever the number of elements it loads or lists.
const withheldByContext = new WeakMap<AuthContext, Map<string, Promise<string[]>>>();

export const registerWithheldElements = (entityType: string, provider: WithheldElementsProvider) => {
  WITHHELD_ELEMENTS_PROVIDERS.set(entityType, [...(WITHHELD_ELEMENTS_PROVIDERS.get(entityType) ?? []), provider]);
};

export const withheldElementIds = (context: AuthContext, user: AuthUser, entityType: string): Promise<string[]> => {
  const providers = WITHHELD_ELEMENTS_PROVIDERS.get(entityType) ?? [];
  if (providers.length === 0) {
    return Promise.resolve([]);
  }
  const known = withheldByContext.get(context) ?? new Map<string, Promise<string[]>>();
  withheldByContext.set(context, known);
  const key = `${user.id}|${entityType}`;
  const cached = known.get(key);
  if (cached) {
    return cached;
  }
  const ids = Promise.all(providers.map((provider) => provider(context, user))).then((lists) => lists.flat());
  known.set(key, ids);
  return ids;
};

/** The element a loader found, or nothing when it is withheld from the reader (as a loader answers for an unknown id). */
export const unlessWithheld = async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, entityType: string, element: T): Promise<T> => {
  if (element && (await withheldElementIds(context, user, entityType)).includes(element.internal_id)) {
    return undefined as unknown as T;
  }
  return element;
};

/** The filters of a listing of the type, with the elements withheld from the reader left out. */
export const withoutWithheldElements = async (context: AuthContext, user: AuthUser, entityType: string, filters?: FilterGroup | null) => {
  const ids = await withheldElementIds(context, user, entityType);
  return ids.length > 0 ? addFilter(filters, 'internal_id', ids, 'not_eq', 'and') : filters;
};
