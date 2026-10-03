import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { fetchQuery } from '../../../relay/environment';
import { HUNT_PACK_MAX_HUNTS, HuntPackExportButton, resolveSelectAllHuntIds } from './HuntPack';

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
