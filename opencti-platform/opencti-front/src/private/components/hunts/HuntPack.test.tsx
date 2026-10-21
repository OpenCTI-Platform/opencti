import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { HUNT_PACK_MAX_HUNTS, HuntPackExportButton, notifyHuntPackImport, resolveSelectAllHuntIds } from './HuntPack';

const dataTableContext = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));

vi.mock('../../../components/dataGrid/components/DataTableContext', () => ({
  useDataTableContext: () => dataTableContext.current,
}));

vi.mock('../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../relay/environment')>()),
  fetchQuery: vi.fn(),
}));

const mockHunts = (ids: string[], globalCount = ids.length) => {
  vi.mocked(fetchQuery).mockReturnValue({
    toPromise: () => Promise.resolve({ hunts: { edges: ids.map((id) => ({ node: { id } })), pageInfo: { globalCount } } }),
  } as unknown as ReturnType<typeof fetchQuery>);
};

describe('HuntPackExportButton', () => {
  beforeEach(() => {
    dataTableContext.current = {};
  });

  it('renders disabled while no hunt is selected', () => {
    dataTableContext.current = {
      useDataTableToggle: { selectedElements: {}, deSelectedElements: {}, selectAll: false },
    };
    testRender(<HuntPackExportButton />);
    expect(screen.getByTestId('hunt-pack-export')).toBeDisabled();
  });

  it('renders enabled on a select-all, even before the first page of the table is loaded', () => {
    dataTableContext.current = {
      useDataTableToggle: { selectedElements: {}, deSelectedElements: {}, selectAll: true },
      data: undefined,
    };
    testRender(<HuntPackExportButton />);
    expect(screen.getByTestId('hunt-pack-export')).toBeEnabled();
  });
});

describe('resolveSelectAllHuntIds', () => {
  beforeEach(() => {
    vi.mocked(fetchQuery).mockReset();
  });

  it('resolves every hunt matching the list options except the deselected ones', async () => {
    mockHunts(['hunt-1', 'hunt-2', 'hunt-3']);
    const filters = { mode: 'and', filters: [{ key: 'hunt_status', values: ['active'] }], filterGroups: [] };
    const ids = await resolveSelectAllHuntIds({ search: 'powershell', filters } as never, { 'hunt-2': true });
    expect(ids).toEqual(['hunt-1', 'hunt-3']);
    expect(vi.mocked(fetchQuery).mock.calls[0][1]).toMatchObject({ search: 'powershell', filters, first: HUNT_PACK_MAX_HUNTS + 1 });
  });

  it('refuses a selection larger than a hunt pack instead of exporting part of it', async () => {
    mockHunts(['hunt-1'], HUNT_PACK_MAX_HUNTS + 5);
    expect(await resolveSelectAllHuntIds({}, { 'hunt-1': true })).toBeNull();
  });
});

describe('notifyHuntPackImport()', () => {
  const t = (message: string, options?: { values?: Record<string, string | number> }) => `${message}|${JSON.stringify(options?.values ?? {})}`;
  const result = (created: number, updated: number) => ({ hunts: [], unresolved_refs: [], created_count: created, updated_count: updated });

  it('names the hunts created and the existing hunts updated by a pack', () => {
    const success = vi.spyOn(MESSAGING$, 'notifySuccess').mockImplementation(() => {});
    notifyHuntPackImport(t, result(2, 1));
    expect(success.mock.calls.map(([message]) => message)).toEqual([
      '{count} hunts imported as drafts|{"count":2}',
      '{count} existing hunts updated from the hunt pack|{"count":1}',
    ]);
    success.mockClear();
    notifyHuntPackImport(t, result(0, 3));
    expect(success.mock.calls.map(([message]) => message)).toEqual(['{count} existing hunts updated from the hunt pack|{"count":3}']);
    success.mockRestore();
  });

  it('never announces a success when the pack imported nothing', () => {
    const success = vi.spyOn(MESSAGING$, 'notifySuccess').mockImplementation(() => {});
    const error = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
    notifyHuntPackImport(t, { ...result(0, 0), unresolved_refs: ['marking-definition--unknown'] });
    expect(success).not.toHaveBeenCalled();
    expect(error.mock.calls.map(([message]) => message)).toEqual([
      'No hunt of the hunt pack was imported: its hunts reference markings or objects unknown on this platform. Create them here, or import a pack whose references exist on this platform.|{}',
      '{count} references of the hunt pack are unknown on this platform and were skipped|{"count":1}',
    ]);
    // A file without any hunt definition says what to check
    error.mockClear();
    notifyHuntPackImport(t, result(0, 0));
    expect(error.mock.calls.map(([message]) => message)).toEqual([
      'No hunt of the hunt pack was imported: the file holds no hunt definition. Check that it is a hunt pack exported from OpenCTI or the XTM Hub (Hunt packs in the documentation).|{}',
    ]);
    success.mockRestore();
    error.mockRestore();
  });
});
