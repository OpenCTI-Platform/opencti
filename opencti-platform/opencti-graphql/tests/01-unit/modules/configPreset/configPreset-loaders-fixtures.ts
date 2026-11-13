import { vi } from 'vitest';
import { fullEntitiesList, fullEntitiesThroughRelationsToList, fullRelationsList, pageEntitiesConnection, storeLoadById } from '../../../../src/database/middleware-loader';
import { buildPagination } from '../../../../src/database/utils';
import { ALL_THEMES } from './configPreset-themes-fixtures';
import { ALL_ROLES } from './configPreset-roles-fixtures';
import { ALL_GROUPS, GROUP_ALLOWED_MARKINGS, GROUP_ROLE_RELATIONS } from './configPreset-groups-fixtures';
import { ALL_MARKINGS } from './configPreset-markings-fixtures';
import { ALL_LABELS } from './configPreset-labels-fixtures';
import { ALL_EXCLUSION_LISTS } from './configPreset-exclusionLists-fixtures';
import { ALL_KILL_CHAIN_PHASES } from './configPreset-killChainPhases-fixtures';
import { ALL_VOCABULARIES } from './configPreset-vocabularies-fixtures';
import { ALL_STATUS_TEMPLATES } from './configPreset-statusTemplates-fixtures';
import { ALL_CASE_TEMPLATES, ALL_TASK_TEMPLATES } from './configPreset-caseTemplates-fixtures';
import { ALL_CONNECTORS } from './configPreset-connectors-fixtures';

interface ListingArgs {
  search?: string | null;
  filters?: { filters: { key: string[]; values: string[]; operator?: string }[] };
}

// The entities of the fixtures, by entity type
const FIXTURE_ENTITIES: Record<string, { id: string; name?: string; definition?: string; value?: string }[]> = {
  Theme: ALL_THEMES,
  Role: ALL_ROLES,
  Group: ALL_GROUPS,
  'Marking-Definition': ALL_MARKINGS,
  Label: ALL_LABELS,
  ExclusionList: ALL_EXCLUSION_LISTS,
  'Kill-Chain-Phase': ALL_KILL_CHAIN_PHASES,
  Vocabulary: ALL_VOCABULARIES,
  StatusTemplate: ALL_STATUS_TEMPLATES,
  'Case-Template': ALL_CASE_TEMPLATES,
  'Task-Template': ALL_TASK_TEMPLATES,
  Connector: ALL_CONNECTORS,
};
const labelOf = (entity: { name?: string; definition?: string; value?: string }) => entity.name ?? entity.definition ?? entity.value ?? '';

// The types the engine sorts by other fields than their name, and searches in other fields
const FIXTURE_LISTINGS: Record<string, { sortFields: string[]; searchFields: string[] }> = {
  'Kill-Chain-Phase': { sortFields: ['kill_chain_name', 'x_opencti_order'], searchFields: ['kill_chain_name', 'phase_name'] },
  Vocabulary: { sortFields: ['category', 'order', 'name'], searchFields: ['category', 'name'] },
};
const read = (entity: object, field: string) => (entity as Record<string, unknown>)[field];
const compare = (a: unknown, b: unknown) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b)));
const sortOf = (type: string | undefined, entity: { name?: string; definition?: string; value?: string }) => {
  const listing = type ? FIXTURE_LISTINGS[type] : undefined;
  return listing ? read(entity, listing.sortFields[0]) : labelOf(entity);
};

// The eq / not_eq filters and the search the families send, applied like the engine does, sorted by name or by the fields of the type
const listLikeTheEngine = (type: string | undefined, args: ListingArgs = {}) => {
  const entities = type ? FIXTURE_ENTITIES[type] : undefined;
  const listing = type ? FIXTURE_LISTINGS[type] : undefined;
  const matchesSearch = (entity: { name?: string; definition?: string; value?: string }, search: string) => {
    if (!listing) {
      return labelOf(entity).toLowerCase().includes(search);
    }
    return listing.searchFields.some((field) => {
      const value = read(entity, field);
      return typeof value === 'string' && value.toLowerCase().includes(search);
    });
  };
  return entities
    ?.filter((entity) => (args.filters?.filters ?? []).every(({ key, values, operator }) => {
      const value = (entity as unknown as Record<string, unknown>)[key[0]];
      const matches = values.includes('EXISTS') ? value !== undefined && value !== null : values.map(String).includes(String(value));
      return operator === 'not_eq' ? !matches : matches;
    }))
    .filter((entity) => !args.search || matchesSearch(entity, args.search.toLowerCase()))
    .sort((a, b) => (listing
      ? listing.sortFields.reduce((result, field) => result || compare(read(a, field), read(b, field)), 0)
      : labelOf(a).localeCompare(labelOf(b))));
};

// For a test that mocks fullEntitiesList, pageEntitiesConnection and storeLoadById of the middleware loader:
// the types of the fixtures come from them, any other type listed by fullEntitiesList gets otherEntities
export const mockConfigPresetLoaders = (otherEntities: unknown[] = []) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, types, args) => {
    return (listLikeTheEngine(types?.[0], args as never) ?? otherEntities) as never;
  });
  vi.mocked(pageEntitiesConnection).mockImplementation(async (_ctx, _user, types, args) => {
    const first = args?.first ?? 500;
    const entities = listLikeTheEngine(types?.[0], args as never) ?? [];
    return buildPagination(first, args?.after, entities.slice(0, first).map((node) => ({ node, sort: [sortOf(types?.[0], node)] })), entities.length) as never;
  });
  vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => {
    return Object.values(FIXTURE_ENTITIES).flat().find((entity) => entity.id === id) as never;
  });
  if (vi.isMockFunction(fullRelationsList)) {
    vi.mocked(fullRelationsList).mockImplementation(async (_ctx, _user, _type, args) => {
      const fromIds = [args?.fromId ?? []].flat();
      return GROUP_ROLE_RELATIONS.filter(({ fromId }) => fromIds.includes(fromId)) as never;
    });
  }
  if (vi.isMockFunction(fullEntitiesThroughRelationsToList)) {
    vi.mocked(fullEntitiesThroughRelationsToList).mockImplementation(async (_ctx, _user, fromId) => GROUP_ALLOWED_MARKINGS[fromId as string] as never);
  }
};
