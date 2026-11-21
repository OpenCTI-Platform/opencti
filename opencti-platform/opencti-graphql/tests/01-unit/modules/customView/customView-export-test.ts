import { beforeEach, describe, expect, it, vi } from 'vitest';
import { GraphQLError } from 'graphql';

vi.mock('../../../../src/modules/dashboard/dashboard-utils', () => ({ convertDashboardManifestIds: vi.fn() }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  logApp: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { logApp } from '../../../../src/config/conf';
import { DatabaseError, FunctionalError } from '../../../../src/config/errors';
import { convertDashboardManifestIds } from '../../../../src/modules/dashboard/dashboard-utils';
import { exportCustomViewToBundle } from '../../../../src/modules/customView/customView-export';
import type { BasicStoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { fromB64, toB64 } from '../../../../src/utils/base64';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const manifest = toB64({ config: {}, widgets: { widget1: { id: 'widget1', dataSelection: [] } } }) as string;
const view = (overrides: Record<string, unknown> = {}) => ({
  id: 'view-id', name: 'Executive overview', target_entity_type: 'Report', description: 'The executives', manifest, enabled: true, default: true, slug: 'executive-overview', ...overrides,
}) as unknown as BasicStoreEntityCustomView;

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(convertDashboardManifestIds).mockImplementation((async (_context: AuthContext, _user: AuthUser, encoded: string) => `converted:${encoded}`) as never);
});

describe('Custom view export to a bundle', () => {
  it('writes what the view is, and neither whether it is enabled nor the default of its entity type', async () => {
    expect(await exportCustomViewToBundle(context, user, view())).toEqual({
      name: 'Executive overview', target_entity_type: 'Report', description: 'The executives', manifest: `converted:${manifest}`,
    });
  });

  it('converts the ids to standard ids, and keeps a saved filter that does not exist instead of failing the export', async () => {
    await exportCustomViewToBundle(context, user, view());
    expect(convertDashboardManifestIds).toHaveBeenCalledWith(context, user, manifest, 'internal', { keepMissingSavedFilters: true });
  });

  it('strips the variables and the presets that a custom view never keeps, before the conversion', async () => {
    const withVariables = toB64({ widgets: {}, variables: [{ id: 'v' }], presets: [] }) as string;
    await exportCustomViewToBundle(context, user, view({ manifest: withVariables }));
    const given = fromB64<Record<string, unknown>>(vi.mocked(convertDashboardManifestIds).mock.calls[0][2] as string);
    expect(given).not.toHaveProperty('variables');
    expect(given).not.toHaveProperty('presets');
  });

  it('always writes the description, empty or not, and no manifest for a view that has none', async () => {
    const exported = await exportCustomViewToBundle(context, user, view({ description: undefined, manifest: undefined }));
    expect(exported).toEqual({ name: 'Executive overview', target_entity_type: 'Report', description: '' });
    expect(convertDashboardManifestIds).not.toHaveBeenCalled();
  });

  describe('a manifest the platform cannot read', () => {
    it.each([
      ['a widget that has no data selection (TypeError)', new TypeError('dataSelection.map is not a function')],
      ['a value that is not base64 json (SyntaxError)', new SyntaxError('Unexpected token')],
      ['a saved filter that cannot be parsed (functional error)', FunctionalError('Failed to parse saved filter')],
    ])('is exported as stored with a warning, so that it does not fail the whole export: %s', async (_label, error) => {
      vi.mocked(convertDashboardManifestIds).mockRejectedValue(error);
      const exported = await exportCustomViewToBundle(context, user, view());
      expect(exported).toMatchObject({ name: 'Executive overview', manifest });
      expect(logApp.warn).toHaveBeenCalledWith(expect.stringContaining('exported as stored'), expect.objectContaining({ custom_view_id: 'view-id' }));
    });

    it('does not hide a failure of the platform itself', async () => {
      vi.mocked(convertDashboardManifestIds).mockRejectedValue(DatabaseError('Search timeout'));
      await expect(exportCustomViewToBundle(context, user, view())).rejects.toBeInstanceOf(GraphQLError);
      expect(logApp.warn).not.toHaveBeenCalled();
    });
  });
});
