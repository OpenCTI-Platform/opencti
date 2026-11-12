import { beforeEach, describe, expect, it, vi } from 'vitest';

type StoredTheme = { _index: string; internal_id: string; name: string; standard_id: string; built_in: boolean };

const { mockCreateInternalObject, mockPageEntitiesConnection, mockElReplace, mockLogAppWarn } = vi.hoisted(() => ({
  mockCreateInternalObject: vi.fn(),
  mockPageEntitiesConnection: vi.fn(),
  mockElReplace: vi.fn(),
  mockLogAppWarn: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, logMigration: { info: vi.fn() }, logApp: { ...actual.logApp, info: vi.fn(), warn: mockLogAppWarn } };
});
vi.mock('../../../../src/domain/internalObject', () => ({
  createInternalObject: mockCreateInternalObject,
  deleteInternalObject: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: mockPageEntitiesConnection,
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', () => ({ updateAttribute: vi.fn() }));
vi.mock('../../../../src/database/redis', () => ({ notify: vi.fn() }));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/database/engine', () => ({ elReplace: mockElReplace }));
vi.mock('../../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({ source: 'migration' })),
  SYSTEM_USER: { id: 'system-user' },
}));

import { addTheme, initDefaultTheme } from '../../../../src/modules/theme/theme-domain';
import { BUILT_IN_THEME_STANDARD_IDS, FILIGRAN_DARK_THEME_NAME, FILIGRAN_LIGHT_THEME_NAME } from '../../../../src/modules/theme/theme-constants';
import { migrateStandardIdsForConfigPreset } from '../../../../src/modules/configPreset/configPreset-migration';
import { generateStandardId, idGenFromData } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_THEME } from '../../../../src/schema/internalObject';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as unknown as AuthContext;
const user = { id: 'system-user' } as unknown as AuthUser;

// In-memory theme store read by the mocked pageEntitiesConnection and written by the mocked elReplace.
let store: StoredTheme[] = [];
const legacyTheme = (name: string, builtIn = true): StoredTheme => ({
  _index: 'opencti_internal_objects-000001',
  internal_id: `internal-${name}`,
  name,
  standard_id: generateStandardId(ENTITY_TYPE_THEME, {}),
  built_in: builtIn,
});

const runMigration = () => migrateStandardIdsForConfigPreset(context);

const seededStandardIds = async () => {
  await initDefaultTheme(context, user);
  return Object.fromEntries(mockCreateInternalObject.mock.calls.map(([, , input]) => [input.name, input.standard_id]));
};

describe('built-in themes fixed standard id', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    store = [];
    mockPageEntitiesConnection.mockImplementation(async () => ({ edges: store.map((node) => ({ node: { ...node } })) }));
    mockCreateInternalObject.mockImplementation(async (_c, _u, input) => ({ id: `internal-${input.name}`, ...input }));
    mockElReplace.mockImplementation(async (_c, _index, id, { doc }) => {
      store = store.map((t) => (t.internal_id === id ? { ...t, ...doc } : t));
    });
  });

  it('keeps the generated theme standard id format', () => {
    const generatedPrefix = generateStandardId(ENTITY_TYPE_THEME, {}).split('--')[0];
    const ids = Object.values(BUILT_IN_THEME_STANDARD_IDS);
    expect(new Set(ids).size).toBe(2);
    ids.forEach((id) => expect(id).toMatch(new RegExp(`^${generatedPrefix}--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)));
    expect(BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_DARK_THEME_NAME]).toBe(idGenFromData(ENTITY_TYPE_THEME, { name: FILIGRAN_DARK_THEME_NAME }));
    expect(BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_LIGHT_THEME_NAME]).toBe(idGenFromData(ENTITY_TYPE_THEME, { name: FILIGRAN_LIGHT_THEME_NAME }));
  });

  it('seeds the built-in themes with their fixed standard id', async () => {
    expect(await seededStandardIds()).toEqual({
      [FILIGRAN_DARK_THEME_NAME]: BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_DARK_THEME_NAME],
      [FILIGRAN_LIGHT_THEME_NAME]: BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_LIGHT_THEME_NAME],
    });
    mockCreateInternalObject.mock.calls.forEach(([, , input]) => expect(input.built_in).toBe(true));
  });

  it('leaves the standard id of a custom theme to the generator', async () => {
    await addTheme(context, user, {
      name: 'My theme',
      theme_background: '#000000',
      theme_paper: '#000000',
      theme_nav: '#000000',
      theme_primary: '#000000',
      theme_secondary: '#000000',
      theme_accent: '#000000',
      theme_text_color: '#ffffff',
    });
    expect(mockCreateInternalObject.mock.calls[0][2]).not.toHaveProperty('standard_id');
  });

  it('migrates existing built-in themes to the ids seeding gives', async () => {
    const seeded = await seededStandardIds();
    const custom = legacyTheme('Custom', false);
    store = [legacyTheme(FILIGRAN_DARK_THEME_NAME), legacyTheme(FILIGRAN_LIGHT_THEME_NAME), custom];
    await runMigration();
    expect(mockElReplace).toHaveBeenCalledTimes(2);
    expect(mockElReplace).toHaveBeenCalledWith(expect.anything(), 'opencti_internal_objects-000001', `internal-${FILIGRAN_DARK_THEME_NAME}`, { doc: { standard_id: seeded[FILIGRAN_DARK_THEME_NAME] } });
    expect(Object.fromEntries(store.filter((t) => t.built_in).map((t) => [t.name, t.standard_id]))).toEqual(seeded);
    expect(store.find((t) => t.name === 'Custom')).toEqual(custom);
  });

  it('is idempotent', async () => {
    store = [legacyTheme(FILIGRAN_DARK_THEME_NAME), legacyTheme(FILIGRAN_LIGHT_THEME_NAME)];
    await runMigration();
    const afterFirstRun = structuredClone(store);
    mockElReplace.mockClear();
    await runMigration();
    expect(mockElReplace).not.toHaveBeenCalled();
    expect(store).toEqual(afterFirstRun);
  });

  it('logs a missing built-in theme and migrates the other one', async () => {
    // A custom theme reusing the name of the missing built-in must not be rewritten.
    store = [legacyTheme(FILIGRAN_DARK_THEME_NAME), legacyTheme(FILIGRAN_LIGHT_THEME_NAME, false)];
    await expect(runMigration()).resolves.toBeUndefined();
    expect(mockElReplace).toHaveBeenCalledTimes(1);
    expect(store[0].standard_id).toBe(BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_DARK_THEME_NAME]);
    expect(store[1].standard_id).not.toBe(BUILT_IN_THEME_STANDARD_IDS[FILIGRAN_LIGHT_THEME_NAME]);
    expect(mockLogAppWarn).toHaveBeenCalledWith(expect.stringContaining(`${FILIGRAN_LIGHT_THEME_NAME} built-in theme not found`));
  });
});
