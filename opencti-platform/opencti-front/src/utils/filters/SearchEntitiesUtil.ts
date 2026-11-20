import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { isStixObjectTypes, ME_FILTER_VALUE } from './filtersUtils';
import { removeAccentsAndLowerCase } from '../String';

type MemberNode = { id: string; entity_type: string; name: string };
type MemberEdges = { edges?: ReadonlyArray<{ node: MemberNode } | null | undefined> | null } | null | undefined;

const memberOption = ({ id, entity_type, name }: MemberNode): FilterOptionValue => ({
  label: name,
  value: id,
  type: entity_type,
  group: entity_type,
});

/**
 * Options of a members search, in the order getOptionsFromEntities keeps when a term is typed: the @me user (if
 * given), then the members found by the search, most relevant first, then the built-in accounts. The built-in
 * accounts (SYSTEM, RULE MANAGER...) are not searched, so they come after the ranked members. They and @me are only
 * added when the filter targets users.
 */
export const buildMembersOptions = (
  data: { members?: MemberEdges; systemMembers?: MemberEdges } | null | undefined,
  entityTypes: string[],
  meOption?: FilterOptionValue,
): FilterOptionValue[] => {
  const toOptions = (connection: MemberEdges) => (connection?.edges ?? [])
    .flatMap((edge) => (edge?.node ? [memberOption(edge.node)] : []));
  const targetsUsers = entityTypes.includes('User');
  return [
    ...(targetsUsers && meOption ? [meOption] : []),
    ...toOptions(data?.members),
    ...(targetsUsers ? toOptions(data?.systemMembers) : []),
  ];
};

// "No label" and the dynamic @me user stay at the top of the list
const pinnedRank = (option: FilterOptionValue) => {
  if (!option.value) return 0;
  if (option.value === ME_FILTER_VALUE) return 1;
  return 2;
};

/**
 * Options of the entities found by the search, "No label" and the dynamic @me user first.
 * When a term is typed, the options keep the order the search returned them in: the most relevant first, as the search
 * engine ranks its results by score. Options of the same group are kept together, as an autocomplete only groups
 * consecutive options, and the groups come in the order of their first shown option, so the group of the most relevant
 * shown entity comes first. When nothing is typed, there is no relevance to keep: groups then labels are alphabetical.
 */
export const getOptionsFromEntities = (
  entities: Record<string, FilterOptionValue[]>,
  searchScope: Record<string, string[]>,
  filterKey: string,
  searchTerm = '',
): FilterOptionValue[] => {
  let filteredOptions: FilterOptionValue[] = [];
  if (isStixObjectTypes.includes(filterKey)) {
    if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
      filteredOptions = (entities[filterKey] || [])
        .filter((n) => searchScope[filterKey].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)));
    } else {
      filteredOptions = (entities[filterKey] || []);
    }
  } else if (entities[filterKey]) {
    filteredOptions = entities[filterKey];
  }
  // In case of entity we group by type
  const options = filteredOptions.map((f) => (!f.group && f.parentTypes ? { ...f, group: f.type } : f));
  if (!searchTerm.trim()) {
    return options.sort((a, b) => pinnedRank(a) - pinnedRank(b)
      || (a.group ?? '').localeCompare(b.group ?? '')
      || (a.label ?? '').localeCompare(b.label ?? ''));
  }
  // The autocomplete then only shows the options whose label contains the typed term, case and accent insensitive
  // (default filter of MUI Autocomplete). An entity the search found on another attribute (description, aliases)
  // is hidden, so it must not move its group up: a group comes in the order of its first shown option, then of its
  // first option if none is shown.
  const term = removeAccentsAndLowerCase(searchTerm);
  const isShown = (option: FilterOptionValue) => removeAccentsAndLowerCase(option.label ?? '').includes(term);
  const groupOrder = new Map<string, number>();
  [...options.filter(isShown), ...options].forEach(({ group }) => {
    if (!groupOrder.has(group ?? '')) groupOrder.set(group ?? '', groupOrder.size);
  });
  // The sort is stable: within a group, the options keep the order of the search
  return options.sort((a, b) => pinnedRank(a) - pinnedRank(b)
    || (groupOrder.get(a.group ?? '') ?? 0) - (groupOrder.get(b.group ?? '') ?? 0));
};
