import { createFilterOptions } from '@mui/material';
import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { isStixObjectTypes, ME_FILTER_VALUE } from './filtersUtils';

const optionLabel = (option: FilterOptionValue) => option.label ?? '';

/**
 * Filter of the entity filter autocomplete (FilterEntityAutocomplete): it only shows the options whose label contains
 * the typed term, case and accent insensitive. getOptionsFromEntities uses the same filter to know which options are
 * shown, so changing it here changes both.
 */
export const filterEntityOptions = createFilterOptions<FilterOptionValue>({ stringify: optionLabel });

type MemberNode = { id: string; entity_type: string; name: string };
type MemberEdges = { edges?: ReadonlyArray<{ node: MemberNode } | null | undefined> | null } | null | undefined;

const memberOption = ({ id, entity_type, name }: MemberNode): FilterOptionValue => ({
  label: name,
  value: id,
  type: entity_type,
  group: entity_type,
});

/**
 * Tags the options found by a search for a typed term: the search engine ranks them by relevance, an order
 * getOptionsFromEntities keeps. The options of a search without a term, or of a list nobody searches (markings, enums,
 * cached creators...), are not tagged and stay alphabetical.
 */
export const rankOptions = <T extends { ranked?: boolean }>(options: T[], searchTerm: string): T[] => (
  searchTerm.trim() ? options.map((option) => ({ ...option, ranked: true })) : options
);

/**
 * Options of a members search: the @me user (if given), then the members found by the search, ranked by relevance when
 * a term is typed, then the built-in accounts. The built-in accounts (SYSTEM, RULE MANAGER...) are not searched, so
 * they are not ranked and come after the searched members. They and @me are only added when the filter targets users.
 */
export const buildMembersOptions = (
  data: { members?: MemberEdges; systemMembers?: MemberEdges } | null | undefined,
  entityTypes: string[],
  { meOption, searchTerm = '' }: { meOption?: FilterOptionValue; searchTerm?: string } = {},
): FilterOptionValue[] => {
  const toOptions = (connection: MemberEdges) => (connection?.edges ?? [])
    .flatMap((edge) => (edge?.node ? [memberOption(edge.node)] : []));
  const targetsUsers = entityTypes.includes('User');
  return [
    ...(targetsUsers && meOption ? [meOption] : []),
    ...rankOptions(toOptions(data?.members), searchTerm),
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
 * When a term is typed, the options ranked by the search (see rankOptions) keep its order: the most relevant first.
 * Options of the same group are kept together, as an autocomplete only groups consecutive options, and the groups come
 * in the order of their first shown ranked option, so the group of the most relevant shown entity comes first.
 * The options without relevance (nothing typed, or a list nobody searches) stay alphabetical: groups then labels, after
 * the ranked ones.
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
  // A ranked option only keeps its rank while a term is typed: without a term, there is no relevance to keep
  const hasTerm = !!searchTerm.trim();
  const isRanked = (option: FilterOptionValue) => hasTerm && !!option.ranked;
  // The autocomplete then only shows the options its filter keeps (filterEntityOptions). An entity the search found on
  // another attribute (description, aliases) is hidden, so it must not move its group up: a group comes in the order of
  // its first shown ranked option, then of its first ranked option if none is shown, then alphabetically if it has no
  // ranked option.
  const shownOptions = new Set(filterEntityOptions(options, { inputValue: searchTerm, getOptionLabel: optionLabel }));
  const isShown = (option: FilterOptionValue) => shownOptions.has(option);
  const rankedOptions = options.filter(isRanked);
  const unrankedGroups = options.filter((o) => !isRanked(o)).map(({ group }) => group ?? '').sort((a, b) => a.localeCompare(b));
  const groupOrder = new Map<string, number>();
  [...rankedOptions.filter(isShown).map(({ group }) => group ?? ''), ...rankedOptions.map(({ group }) => group ?? ''), ...unrankedGroups]
    .forEach((group) => {
      if (!groupOrder.has(group)) groupOrder.set(group, groupOrder.size);
    });
  // The sort is stable: within a group, the ranked options keep the order of the search, then come the others by label
  return options.sort((a, b) => pinnedRank(a) - pinnedRank(b)
    || (groupOrder.get(a.group ?? '') ?? 0) - (groupOrder.get(b.group ?? '') ?? 0)
    || Number(isRanked(b)) - Number(isRanked(a))
    || (isRanked(a) ? 0 : (a.label ?? '').localeCompare(b.label ?? '')));
};
