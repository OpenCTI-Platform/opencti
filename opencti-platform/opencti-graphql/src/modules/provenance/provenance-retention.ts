import { FilterMode, FilterOperator, type FilterGroup, RetentionRuleScope } from '../../generated/graphql';
import type { FilterGroupWithNested } from '../../database/middleware-loader';
import type { AuthContext } from '../../types/user';
import { ATTRIBUTE_CONFLICTS } from './provenance-types';
import { applyProvenanceUpdate, type ProvenanceTarget } from './provenance-write';

export const RETENTION_SCOPE_CONFLICTS: string = RetentionRuleScope.Conflicts;

/**
 * Elements with at least one conflicting value whose last assertion is older than the retention date.
 * The completion of special filter keys turns the values of a nested object attribute into its nested predicates,
 * so the predicate is carried by the values (and by nested for the queries that skip the completion).
 */
export const buildStaleConflictsFilters = (before: string, userFilters?: FilterGroup | null): FilterGroupWithNested => {
  const predicates = [{ key: 'values.last_asserted_at', values: [before], operator: FilterOperator.Lt }];
  return {
    mode: FilterMode.And,
    filters: [{ key: [ATTRIBUTE_CONFLICTS], values: predicates, nested: predicates }],
    filterGroups: userFilters ? [userFilters as FilterGroupWithNested] : [],
  };
};

export const purgeOutdatedConflicts = async (context: AuthContext, element: ProvenanceTarget, before: string) => {
  return applyProvenanceUpdate(context, element, { conflictsPurgeBefore: before });
};
