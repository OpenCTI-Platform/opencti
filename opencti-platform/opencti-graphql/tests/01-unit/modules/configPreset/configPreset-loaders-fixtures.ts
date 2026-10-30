import { vi } from 'vitest';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../../../src/database/middleware-loader';
import { buildPagination } from '../../../../src/database/utils';
import { ALL_THEMES } from './configPreset-themes-fixtures';
import { ALL_ROLES } from './configPreset-roles-fixtures';

interface ListingArgs {
  search?: string | null;
  filters?: { filters: { key: string[]; values: string[]; operator?: string }[] };
}

// The entities of the fixtures, by entity type
const FIXTURE_ENTITIES: Record<string, { id: string; name: string }[]> = {
  Theme: ALL_THEMES,
  Role: ALL_ROLES,
};

// The eq / not_eq filters and the search the families send, applied like the engine does, sorted by name
const listLikeTheEngine = (type: string | undefined, args: ListingArgs = {}) => {
  const entities = type ? FIXTURE_ENTITIES[type] : undefined;
  return entities
    ?.filter((entity) => (args.filters?.filters ?? []).every(({ key, values, operator }) => {
      const matches = values.map(String).includes(String((entity as unknown as Record<string, unknown>)[key[0]]));
      return operator === 'not_eq' ? !matches : matches;
    }))
    .filter((entity) => !args.search || entity.name.toLowerCase().includes(args.search.toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name));
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
    return buildPagination(first, args?.after, entities.slice(0, first).map((node) => ({ node, sort: [node.name] })), entities.length) as never;
  });
  vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => {
    return Object.values(FIXTURE_ENTITIES).flat().find((entity) => entity.id === id) as never;
  });
};
