import type { AuthContext, AuthUser } from '../types/user';
import type { FilterGroup } from '../generated/graphql';

/**
 * A gate returns the query clause a document must match for its stored value of the gated attributes to be used by a
 * filter, an aggregation or a date histogram: the attributes of a module whose values a reader may only use where the
 * module's policy shows them, whatever a cleanup that failed or has not run yet left in the index.
 */
export type AttributeQueryGate = (context: AuthContext, user: AuthUser) => Promise<Record<string, unknown>>;

const ATTRIBUTE_QUERY_GATES = new Map<string, AttributeQueryGate>();

export const registerAttributeQueryGate = (attributes: string[], gate: AttributeQueryGate) => {
  attributes.forEach((attribute) => ATTRIBUTE_QUERY_GATES.set(attribute, gate));
};

const collectFilterKeys = (group: FilterGroup | null | undefined, keys: Set<string>) => {
  if (!group) {
    return;
  }
  (group.filters ?? []).forEach((filter) => {
    const filterKeys: string[] = Array.isArray(filter.key) ? filter.key : [filter.key];
    filterKeys.forEach((key) => keys.add(key));
  });
  (group.filterGroups ?? []).forEach((subGroup) => collectFilterKeys(subGroup, keys));
};

/** The clauses of the gates of every attribute the filters or the aggregation read, each gate once. */
export const attributeGateClauses = async (
  context: AuthContext,
  user: AuthUser,
  read: { filters?: FilterGroup | null; attributes?: Array<string | null | undefined> },
): Promise<Record<string, unknown>[]> => {
  if (ATTRIBUTE_QUERY_GATES.size === 0) {
    return [];
  }
  const keys = new Set<string>();
  collectFilterKeys(read.filters, keys);
  (read.attributes ?? []).forEach((attribute) => {
    if (attribute) keys.add(attribute);
  });
  const gates = new Set<AttributeQueryGate>();
  keys.forEach((key) => {
    const gate = ATTRIBUTE_QUERY_GATES.get(key);
    if (gate) gates.add(gate);
  });
  return Promise.all([...gates].map((gate) => gate(context, user)));
};
