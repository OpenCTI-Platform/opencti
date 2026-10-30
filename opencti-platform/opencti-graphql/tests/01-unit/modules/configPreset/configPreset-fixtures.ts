import { vi } from 'vitest';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../../../src/database/middleware-loader';
import { buildPagination } from '../../../../src/database/utils';
import type { BasicStoreEntityKillChainPhase } from '../../../../src/modules/killChainPhase/killChainPhase-types';
import type { BasicStoreEntityLabel } from '../../../../src/modules/label/label-types';
import type { BasicStoreEntityVocabulary } from '../../../../src/modules/vocabulary/vocabulary-types';
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

export const killChainPhase = {
  id: 'phase-id',
  internal_id: 'phase-id',
  standard_id: 'kill-chain-phase--4c3b2a19-8e7d-5f6a-9b0c-1d2e3f4a5b6c',
  entity_type: 'Kill-Chain-Phase',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  kill_chain_name: 'mitre-attack',
  phase_name: 'execution',
  x_opencti_order: 2,
} as unknown as BasicStoreEntityKillChainPhase;

export const otherKillChainPhase = {
  ...killChainPhase,
  id: 'other-phase-id',
  internal_id: 'other-phase-id',
  standard_id: 'kill-chain-phase--7e6d5c4b-3a29-5180-9f8e-7d6c5b4a3921',
  phase_name: 'initial-access',
  x_opencti_order: 1,
} as unknown as BasicStoreEntityKillChainPhase;

export const disarmKillChainPhase = {
  ...killChainPhase,
  id: 'disarm-phase-id',
  internal_id: 'disarm-phase-id',
  standard_id: 'kill-chain-phase--0a1b2c3d-4e5f-5061-8273-94a5b6c7d8e9',
  kill_chain_name: 'disarm',
  phase_name: 'plan-strategy',
  x_opencti_order: 0,
} as unknown as BasicStoreEntityKillChainPhase;

// By kill chain, then by order in the kill chain
export const ALL_KILL_CHAIN_PHASES = [killChainPhase, otherKillChainPhase, disarmKillChainPhase];

// The way the platform creates its own entries (see openVocabularies): no description is '', no aliases [], no order 0
const storedVocabulary = {
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  entity_type: 'Vocabulary',
  builtIn: false,
};

// An entry of the platform that nobody modified: not exported, its category is when another entry of it is
export const defaultVocabulary = {
  ...storedVocabulary,
  id: 'default-vocabulary-id',
  internal_id: 'default-vocabulary-id',
  standard_id: 'vocabulary--11111111-2222-5333-8444-555555555555',
  name: 'threat-report',
  category: 'report_types_ov',
  description: '',
  aliases: [],
  order: 0,
} as unknown as BasicStoreEntityVocabulary;

// The only entry of its category the fixtures have, and nobody modified it: the category is not exported
export const untouchedVocabulary = {
  ...defaultVocabulary,
  id: 'untouched-vocabulary-id',
  internal_id: 'untouched-vocabulary-id',
  standard_id: 'vocabulary--99999999-8888-5777-8666-555555555555',
  name: 'alert',
  category: 'incident_type_ov',
  description: 'An alert.',
} as unknown as BasicStoreEntityVocabulary;

// An entry of the platform whose description was modified: exported
export const modifiedVocabulary = {
  ...storedVocabulary,
  id: 'modified-vocabulary-id',
  internal_id: 'modified-vocabulary-id',
  standard_id: 'vocabulary--66666666-7777-5888-8999-aaaaaaaaaaaa',
  name: 'high',
  category: 'integrity_level_ov',
  description: 'Our own description of a high integrity',
  aliases: ['elevated'],
  order: 3,
} as unknown as BasicStoreEntityVocabulary;

// A custom entry: exported
export const customVocabulary = {
  ...storedVocabulary,
  id: 'custom-vocabulary-id',
  internal_id: 'custom-vocabulary-id',
  standard_id: 'vocabulary--bbbbbbbb-cccc-5ddd-8eee-ffffffffffff',
  name: 'fimi-report',
  category: 'report_types_ov',
  description: 'Foreign information manipulation',
  aliases: ['fimi'],
  order: 5,
} as unknown as BasicStoreEntityVocabulary;

export const otherCustomVocabulary = {
  ...customVocabulary,
  id: 'other-custom-vocabulary-id',
  internal_id: 'other-custom-vocabulary-id',
  standard_id: 'vocabulary--00000000-1111-5222-8333-444444444444',
  name: 'sev-x',
  category: 'case_severity_ov',
  description: '',
  aliases: [],
  order: 0,
} as unknown as BasicStoreEntityVocabulary;

export const ALL_VOCABULARIES = [defaultVocabulary, untouchedVocabulary, modifiedVocabulary, customVocabulary, otherCustomVocabulary];

interface ListingArgs {
  search?: string | null;
  filters?: { filters: { key: string[]; values: string[]; operator?: string }[] };
}

// The eq / not_eq filters and the search the families send, applied like the engine does, sorted by the given fields
const listLikeTheEngine = <T extends object>(entities: T[], sortFields: string[], args: ListingArgs = {}, searchFields = sortFields) => {
  const read = (entity: T, key: string) => (entity as Record<string, unknown>)[key];
  const compare = (a: unknown, b: unknown) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b)));
  return entities
    .filter((entity) => (args.filters?.filters ?? []).every(({ key, values, operator }) => {
      const matches = values.map(String).includes(String(read(entity, key[0])));
      return operator === 'not_eq' ? !matches : matches;
    }))
    .filter((entity) => !args.search || searchFields.some((field) => {
      const value = read(entity, field);
      return typeof value === 'string' && value.toLowerCase().includes(args.search!.toLowerCase());
    }))
    .sort((a, b) => sortFields.reduce((result, field) => result || compare(read(a, field), read(b, field)), 0));
};

export const listThemesLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_THEMES, ['name'], args);
export const listLabelsLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_LABELS, ['value'], args);
export const listVocabulariesLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_VOCABULARIES, ['category', 'order', 'name'], args);
export const listKillChainPhasesLikeTheEngine = (args: ListingArgs = {}) => listLikeTheEngine(ALL_KILL_CHAIN_PHASES, ['kill_chain_name', 'x_opencti_order'], args, ['kill_chain_name', 'phase_name']);

// The entities of a type the fixtures know, listed like the engine does
const listFixtures = (type: string | undefined, args: unknown) => {
  switch (type) {
    case 'Label':
      return listLabelsLikeTheEngine(args as ListingArgs);
    case 'Kill-Chain-Phase':
      return listKillChainPhasesLikeTheEngine(args as ListingArgs);
    case 'Vocabulary':
      return listVocabulariesLikeTheEngine(args as ListingArgs);
    case 'Theme':
      return listThemesLikeTheEngine(args as ListingArgs);
    default:
      return undefined;
  }
};

// For a test that mocks fullEntitiesList, pageEntitiesConnection and storeLoadById of the middleware loader:
// the themes, the labels, the kill chain phases and the vocabularies come from the fixtures, any other type listed by fullEntitiesList gets otherEntities
export const mockEntityLoaders = (otherEntities: unknown[] = []) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, types, args) => {
    return (listFixtures(types?.[0], args) ?? otherEntities) as never;
  });
  vi.mocked(pageEntitiesConnection).mockImplementation(async (_ctx, _user, types, args) => {
    const first = args?.first ?? 500;
    const entities = listFixtures(types?.[0], args) ?? [];
    const sortOf = (entity: unknown) => ['name', 'value', 'kill_chain_name'].map((field) => (entity as Record<string, unknown>)[field]).find((value) => value !== undefined);
    return buildPagination(first, args?.after, entities.slice(0, first).map((node) => ({ node, sort: [sortOf(node)] })), entities.length) as never;
  });
  const everyEntity = [...ALL_THEMES, ...ALL_LABELS, ...ALL_KILL_CHAIN_PHASES, ...ALL_VOCABULARIES];
  vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => everyEntity.find((entity) => entity.id === id) as never);
};
