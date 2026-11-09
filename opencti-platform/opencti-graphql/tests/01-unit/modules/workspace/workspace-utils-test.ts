import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', () => ({
  internalFindByIds: vi.fn(),
}));

import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { convertDashboardIds } from '../../../../src/modules/workspace/workspace-utils';
import type { StoreDashboardVariable } from '../../../../src/modules/workspace/workspace-variables-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = {} as AuthContext;
const user = {} as AuthUser;
const SECTOR_ID = '11111111-1111-4111-8111-111111111111';
const SECTOR_STIX = 'identity--11111111-1111-4111-8111-111111111111';
const MERGED_STIX = 'identity--22222222-2222-4222-8222-222222222222';
const MARKING_ID = '33333333-3333-4333-8333-333333333333';
const MARKING_STIX = 'marking-definition--33333333-3333-4333-8333-333333333333';
const ENTITIES = {
  [SECTOR_ID]: { internal_id: SECTOR_ID, standard_id: SECTOR_STIX },
  [SECTOR_STIX]: { internal_id: SECTOR_ID, standard_id: SECTOR_STIX },
  // A STIX id kept by the entity it was merged into
  [MERGED_STIX]: { internal_id: SECTOR_ID, standard_id: SECTOR_STIX },
  [MARKING_ID]: { internal_id: MARKING_ID, standard_id: MARKING_STIX },
  [MARKING_STIX]: { internal_id: MARKING_ID, standard_id: MARKING_STIX },
};
const filterOn = (key: string, values: string[]) => ({ mode: 'and', filters: [{ key: [key], values, operator: 'eq', mode: 'or' }], filterGroups: [] });

describe('convertDashboardIds', () => {
  beforeEach(() => {
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(internalFindByIds).mockImplementation(async (_context, _user, ids) => {
      return Object.fromEntries((ids as string[]).filter((id) => id in ENTITIES).map((id) => [id, ENTITIES[id as keyof typeof ENTITIES]])) as never;
    });
  });

  it('should resolve the ids of the widgets and of the variables in a single lookup', async () => {
    const widgets = [{ dataSelection: [{ filters: filterOn('objectMarking', [MARKING_ID]), dynamicFrom: filterOn('id', [SECTOR_ID]) }] }];
    const variables: StoreDashboardVariable[] = [
      { id: 'v1', name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'selection', values: [SECTOR_ID] }, defaultValue: SECTOR_ID },
      { id: 'v2', name: 'Marking', type: 'marking', restriction: { mode: 'filters', filters: filterOn('id', [MARKING_ID]) as never }, defaultValue: null },
      // A text value shaped like an id is not an entity reference
      { id: 'v3', name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: SECTOR_ID },
    ];
    await convertDashboardIds(context, user, widgets, variables, 'internal');
    expect(internalFindByIds).toHaveBeenCalledTimes(1);
    expect(vi.mocked(internalFindByIds).mock.calls[0][2]).toEqual([MARKING_ID, SECTOR_ID]);
    expect(widgets[0].dataSelection[0].filters.filters[0].values).toEqual([MARKING_STIX]);
    expect(widgets[0].dataSelection[0].dynamicFrom.filters[0].values).toEqual([SECTOR_STIX]);
    expect(variables[0]).toMatchObject({ defaultValue: SECTOR_STIX, restriction: { mode: 'selection', values: [SECTOR_STIX] } });
    expect((variables[1].restriction as { filters: { filters: { values: string[] }[] } }).filters.filters[0].values).toEqual([MARKING_STIX]);
    expect(variables[2].defaultValue).toEqual(SECTOR_ID);
  });

  it('should never keep a value twice in a selection once converted on import', async () => {
    const variables: StoreDashboardVariable[] = [
      { id: 'v1', name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'selection', values: [SECTOR_STIX, MERGED_STIX] }, defaultValue: MERGED_STIX },
    ];
    await convertDashboardIds(context, user, [], variables, 'stix');
    expect(variables[0]).toMatchObject({ defaultValue: SECTOR_ID, restriction: { mode: 'selection', values: [SECTOR_ID] } });
  });

  it('should not look anything up without an id to convert', async () => {
    const widgets = [{ dataSelection: [{ filters: filterOn('entity_type', ['Malware']) }] }];
    await convertDashboardIds(context, user, widgets, [], 'internal');
    expect(internalFindByIds).not.toHaveBeenCalled();
    expect(widgets[0].dataSelection[0].filters.filters[0].values).toEqual(['Malware']);
  });
});
