import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/domain/markingDefinition', () => ({
  addAllowedMarkingDefinition: vi.fn(),
  findById: vi.fn(),
  markingDefinitionEditField: vi.fn(),
}));
vi.mock('../../../../src/domain/group', () => ({ findAllGroups: vi.fn() }));
vi.mock('../../../../src/modules/user/sensitive-config-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/sensitive-config-import')>()),
  isConfigImportSensitiveChangeAllowed: vi.fn(),
}));

import { addAllowedMarkingDefinition, findById, markingDefinitionEditField } from '../../../../src/domain/markingDefinition';
import { findAllGroups } from '../../../../src/domain/group';
import { isConfigImportSensitiveChangeAllowed } from '../../../../src/modules/user/sensitive-config-import';
import { BUILT_IN_MARKING_STANDARD_IDS, importMarking, markingStandardId } from '../../../../src/modules/markingDefinition/marking-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };

const markingConfiguration = (overrides: Record<string, unknown> = {}) => ({
  definition_type: 'INTERNAL',
  definition: 'INTERNAL:SOC',
  x_opencti_color: '#123456',
  x_opencti_order: 7,
  ...overrides,
});
const existing = { id: 'soc-internal-id', standard_id: markingStandardId('INTERNAL', 'INTERNAL:SOC'), definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_color: '#123456', x_opencti_order: 7 };

const expectNothingWritten = () => {
  expect(addAllowedMarkingDefinition).not.toHaveBeenCalled();
  expect(markingDefinitionEditField).not.toHaveBeenCalled();
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(true);
  vi.mocked(findById).mockResolvedValue(undefined as never);
  vi.mocked(findAllGroups).mockResolvedValue([] as never);
  vi.mocked(addAllowedMarkingDefinition).mockImplementation(async (_ctx, _user, marking) => ({ id: 'created-id', ...marking }) as never);
});

describe('importMarking', () => {
  it('refuses an invalid marking, without writing', async () => {
    const results = await Promise.all([{ definition: ' ' }, { x_opencti_color: '' }, { x_opencti_order: 1.5 }, { unknown: true }]
      .map((overrides) => importMarking(context, user, markingConfiguration(overrides), overwrite)));
    results.forEach((result) => expect(result).toMatchObject({ status: 'failed', code: 'invalid' }));
    expectNothingWritten();
  });

  it('accepts any color the platform accepts', async () => {
    const results = await Promise.all(['red', '#fff'].map((color) => importMarking(context, user, markingConfiguration({ x_opencti_color: color }), overwrite)));
    results.forEach((result) => expect(result).toMatchObject({ status: 'created' }));
  });

  it('skips the built-in markings, the same on every platform', async () => {
    expect(BUILT_IN_MARKING_STANDARD_IDS).toHaveLength(9);
    const result = await importMarking(context, user, markingConfiguration({ definition_type: 'TLP', definition: 'TLP:RED' }), overwrite);
    expect(result).toMatchObject({ status: 'skipped', code: 'built_in', reason: 'Built-in marking', exists: true });
    expect(findById).not.toHaveBeenCalled();
    expectNothingWritten();
  });

  it('creates a marking that is absent, and writes nothing on a dry run', async () => {
    expect(await importMarking(context, user, markingConfiguration(), { ...overwrite, dryRun: true })).toMatchObject({ status: 'created', exists: false, reason: undefined });
    expectNothingWritten();
    const result = await importMarking(context, user, markingConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'created', marking: { id: 'created-id' } });
    expect(addAllowedMarkingDefinition).toHaveBeenCalledWith(context, user, { definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_order: 7, x_opencti_color: '#123456' });
  });

  it('says that the groups that get new markings automatically get the marking it creates', async () => {
    vi.mocked(findAllGroups).mockResolvedValue([{ id: 'auto-group-id' }] as never);
    const result = await importMarking(context, user, markingConfiguration(), { ...overwrite, dryRun: true });
    expect(result.reason).toEqual('Groups that get new markings automatically get this one');
  });

  it('overwrites the color and the order that differ, and says so when the order changes', async () => {
    vi.mocked(findById).mockResolvedValue(existing as never);
    const result = await importMarking(context, user, markingConfiguration({ x_opencti_color: '#654321', x_opencti_order: 9 }), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true, reason: 'The order of the marking changes' });
    expect(markingDefinitionEditField).toHaveBeenCalledWith(context, user, existing.id, [
      { key: 'x_opencti_color', value: ['#654321'] },
      { key: 'x_opencti_order', value: [9] },
    ]);
  });

  it('leaves untouched the values that are null or the same, and says the marking is already up to date', async () => {
    vi.mocked(findById).mockResolvedValue(existing as never);
    const result = await importMarking(context, user, markingConfiguration({ x_opencti_color: null }), overwrite);
    expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expectNothingWritten();
  });

  it('reads a marking stored without an order as the order 0, so that its export is up to date', async () => {
    const { x_opencti_order: _, ...unordered } = existing;
    vi.mocked(findById).mockResolvedValue(unordered as never);
    expect(await importMarking(context, user, markingConfiguration({ x_opencti_order: 0 }), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expectNothingWritten();
  });

  it('refuses a marking that exists in ADD mode, and one the user cannot change', async () => {
    vi.mocked(findById).mockResolvedValue(existing as never);
    expect(await importMarking(context, user, markingConfiguration(), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(false);
    const result = await importMarking(context, user, markingConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'sensitive_config', reason: 'Requires the right to manage the sensitive configuration' });
    expect(isConfigImportSensitiveChangeAllowed).toHaveBeenCalledWith(context, user, 'markings', existing.standard_id);
    expectNothingWritten();
  });
});
