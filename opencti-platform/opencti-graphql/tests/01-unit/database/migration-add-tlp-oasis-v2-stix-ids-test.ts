import { beforeEach, expect, it, vi } from 'vitest';
import { up } from '../../../src/migrations/1794995400000-add-tlp-oasis-v2-stix-ids';
import { logMigration } from '../../../src/config/conf';
import { DatabaseError } from '../../../src/config/errors';
import { patchAttribute } from '../../../src/database/middleware';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { MARKING_TLP_AMBER, MARKING_TLP_OASIS_V2_ALIASES } from '../../../src/schema/identifier';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';

vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...await importOriginal<any>(),
  logMigration: { info: vi.fn(), warn: vi.fn() },
}));
vi.mock('../../../src/utils/access', () => ({ SYSTEM_USER: {}, executionContext: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ internalLoadById: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ patchAttribute: vi.fn() }));

beforeEach(() => vi.clearAllMocks());

it.each([MARKING_TLP_AMBER, ...MARKING_TLP_OASIS_V2_ALIASES[MARKING_TLP_AMBER]])('skips duplicate id %s and finishes the migration', async (duplicateId) => {
  const reason = 'Id loading expect only one response';
  vi.mocked(internalLoadById).mockImplementation(async (_context, _user, id) => {
    if (id === duplicateId) throw DatabaseError(reason, { id, hits: 2 });
    if (id && id in MARKING_TLP_OASIS_V2_ALIASES) {
      return { internal_id: id, entity_type: ENTITY_TYPE_MARKING_DEFINITION } as any;
    }
    return undefined as any;
  });
  const next = vi.fn();
  await up(next);

  expect(logMigration.warn).toHaveBeenCalledWith(expect.stringContaining(duplicateId));
  expect(logMigration.warn).toHaveBeenCalledWith(expect.stringContaining(reason));
  expect(vi.mocked(patchAttribute).mock.calls.map(([, , id, , patch]) => [id, patch])).toEqual(
    Object.entries(MARKING_TLP_OASIS_V2_ALIASES)
      .filter(([id]) => id !== MARKING_TLP_AMBER)
      .map(([id, aliases]) => [id, { x_opencti_stix_ids: aliases }]),
  );
  expect(next).toHaveBeenCalledTimes(1);
});

it.each([MARKING_TLP_AMBER, ...MARKING_TLP_OASIS_V2_ALIASES[MARKING_TLP_AMBER]])('rethrows non-duplicate error when loading %s', async (failingId) => {
  const failure = DatabaseError('Connection lost');
  vi.mocked(internalLoadById).mockImplementation(async (_context, _user, id) => {
    if (id === failingId) throw failure;
    if (id && id in MARKING_TLP_OASIS_V2_ALIASES) {
      return { internal_id: id, entity_type: ENTITY_TYPE_MARKING_DEFINITION } as any;
    }
    return undefined as any;
  });
  const next = vi.fn();
  await expect(up(next)).rejects.toBe(failure);

  expect(logMigration.warn).not.toHaveBeenCalled();
  expect(vi.mocked(patchAttribute).mock.calls.map(([, , id]) => id)).not.toContain(MARKING_TLP_AMBER);
  expect(next).not.toHaveBeenCalled();
});
