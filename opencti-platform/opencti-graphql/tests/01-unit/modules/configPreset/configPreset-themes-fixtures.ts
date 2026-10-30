import { vi } from 'vitest';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../../../src/database/middleware-loader';
import { buildPagination } from '../../../../src/database/utils';
import type { BasicStoreEntityLabel } from '../../../../src/modules/label/label-types';
import type { BasicStoreEntityTheme } from '../../../../src/modules/theme/theme-types';

const colors = {
  theme_background: '#070d19',
  theme_paper: '#09101e',
  theme_nav: '#070d19',
  theme_primary: '#0fbcff',
  theme_secondary: '#00f1bd',
  theme_accent: '#0f1e38',
  theme_text_color: '#ffffff',
};

// A custom theme with, next to the import format fields, attributes that must never be exported
export const customTheme = {
  id: 'custom-theme-id',
  internal_id: 'custom-theme-id',
  standard_id: 'theme--3f1e0f0a-2a5c-4e1f-9a1d-7d1c6f0b9e21',
  entity_type: 'Theme',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'SOC night',
  built_in: false,
  ...colors,
  theme_logo: 'data:image/png;base64,AAAA',
  theme_logo_collapsed: '',
  theme_logo_login: 'https://example.com/logo.png',
  theme_login_aside_color: '#000000',
  theme_login_aside_gradient_start: null,
  theme_login_aside_gradient_end: null,
  theme_login_aside_image: null,
} as unknown as BasicStoreEntityTheme;

export const otherCustomTheme = {
  ...customTheme,
  id: 'other-theme-id',
  internal_id: 'other-theme-id',
  standard_id: 'theme--8b0d3c1e-5f4a-4a2b-8c3d-1e2f3a4b5c6d',
  name: 'Customer ACME',
} as unknown as BasicStoreEntityTheme;

export const builtInTheme = {
  ...customTheme,
  id: 'dark-theme-id',
  internal_id: 'dark-theme-id',
  standard_id: 'theme--0d8a3f0e-1c2b-4d5e-8f9a-0b1c2d3e4f5a',
  name: 'Filigran Dark',
  built_in: true,
} as unknown as BasicStoreEntityTheme;

export const ALL_THEMES = [builtInTheme, customTheme, otherCustomTheme];

// The theme import format (themeImportSchema), plus the standard id
export const THEME_FILE_FIELDS = [
  'standard_id',
  'name',
  'theme_background',
  'theme_paper',
  'theme_nav',
  'theme_primary',
  'theme_secondary',
  'theme_accent',
  'theme_text_color',
  'theme_logo',
  'theme_logo_collapsed',
  'theme_logo_login',
  'theme_login_aside_color',
  'theme_login_aside_gradient_start',
  'theme_login_aside_gradient_end',
  'theme_login_aside_image',
];

export const customLabel = {
  id: 'custom-label-id',
  internal_id: 'custom-label-id',
  standard_id: 'label--5d2c1a7e-3b4f-5c6d-8e9f-0a1b2c3d4e5f',
  entity_type: 'Label',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  value: 'tlp:amber',
  color: '#ffc107',
} as unknown as BasicStoreEntityLabel;

export const otherLabel = {
  ...customLabel,
  id: 'other-label-id',
  internal_id: 'other-label-id',
  standard_id: 'label--9a8b7c6d-5e4f-5a3b-9c2d-1e0f9a8b7c6d',
  value: 'APT',
  color: '#ff0000',
} as unknown as BasicStoreEntityLabel;

export const ALL_LABELS = [customLabel, otherLabel];

interface ListingArgs {
  search?: string | null;
  filters?: { filters: { key: string[]; values: string[]; operator?: string }[] };
}

// The eq / not_eq filters and the search the families send, applied like the engine does, sorted by the given field
const listLikeTheEngine = <T extends object>(entities: T[], field: string, args: ListingArgs = {}) => {
  const valueOf = (entity: T, key: string) => String((entity as Record<string, unknown>)[key]);
  return entities
    .filter((entity) => (args.filters?.filters ?? []).every(({ key, values, operator }) => {
      const matches = values.map(String).includes(valueOf(entity, key[0]));
      return operator === 'not_eq' ? !matches : matches;
    }))
    .filter((entity) => !args.search || valueOf(entity, field).toLowerCase().includes(args.search.toLowerCase()))
    .sort((a, b) => valueOf(a, field).localeCompare(valueOf(b, field)));
};

export const listThemesLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_THEMES, 'name', args);
export const listLabelsLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_LABELS, 'value', args);

// For a test that mocks fullEntitiesList, pageEntitiesConnection and storeLoadById of the middleware loader:
// the themes and the labels come from the fixtures, any other type listed by fullEntitiesList gets otherEntities
export const mockThemeLoaders = (otherEntities: unknown[] = []) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, types, args) => {
    if (types?.[0] === 'Label') {
      return listLabelsLikeTheEngine(args as never) as never;
    }
    return (types?.[0] === 'Theme' ? listThemesLikeTheEngine(args as never) : otherEntities) as never;
  });
  vi.mocked(pageEntitiesConnection).mockImplementation(async (_ctx, _user, types, args) => {
    const first = args?.first ?? 500;
    const isLabel = types?.[0] === 'Label';
    const entities = isLabel ? listLabelsLikeTheEngine(args as never) : listThemesLikeTheEngine(args as never);
    const sortOf = (entity: unknown) => (isLabel ? (entity as BasicStoreEntityLabel).value : (entity as BasicStoreEntityTheme).name);
    return buildPagination(first, args?.after, entities.slice(0, first).map((node) => ({ node, sort: [sortOf(node)] })), entities.length) as never;
  });
  vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => [...ALL_THEMES, ...ALL_LABELS].find((entity) => entity.id === id) as never);
};
