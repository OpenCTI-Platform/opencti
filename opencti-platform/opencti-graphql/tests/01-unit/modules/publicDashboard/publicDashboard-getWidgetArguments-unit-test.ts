import { describe, expect, it, vi, beforeEach } from 'vitest';

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../../src/database/engine', () => ({
  elLoadById: vi.fn(),
}));

vi.mock('../../../../src/utils/markingDefinition-utils', () => ({
  cleanMarkings: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  computeAvailableMarkings: vi.fn().mockResolvedValue([]),
}));

import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { elLoadById } from '../../../../src/database/engine';
import { getWidgetArguments } from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../../../../src/modules/publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { PUBLIC_DASHBOARD_REFERER } from '../../../../src/utils/access';

const knowledgeCapability = { id: 'capability--knowledge', standard_id: 'capability--knowledge', internal_id: 'capability--knowledge', name: 'KNOWLEDGE' };

const publicDashboard = {
  enabled: true,
  user_id: 'creator-id',
  allowed_markings: [],
  private_manifest: {
    widgets: {
      'widget-1': { dataSelection: ['selection'], parameters: {} },
    },
  },
};

const dashboardCreator = {
  id: 'creator-id',
  capabilities: [{ name: 'SETTINGS_SETACCESSES' }, { name: 'BYPASS' }],
  max_shareable_marking: [],
  allowed_marking: [],
};

describe('getWidgetArguments', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockImplementation(async (_context, _user, entityType) => {
      if (entityType === ENTITY_TYPE_PUBLIC_DASHBOARD) {
        return new Map([['my-dashboard', publicDashboard]]) as any;
      }
      if (entityType === ENTITY_TYPE_USER) {
        return new Map([[dashboardCreator.id, dashboardCreator]]) as any;
      }
      return new Map();
    });
    vi.mocked(elLoadById).mockResolvedValue(knowledgeCapability as any);
  });

  it('returns a user scoped to a single restricted capability', async () => {
    const { user } = await getWidgetArguments({} as any, 'my-dashboard', 'widget-1');

    expect(user.capabilities).toEqual([knowledgeCapability]);
    expect(user.origin?.referer).toBe(PUBLIC_DASHBOARD_REFERER);
  });

  it('keeps the dashboard creator id on the returned user', async () => {
    const { user } = await getWidgetArguments({} as any, 'my-dashboard', 'widget-1');

    expect(user.id).toBe(dashboardCreator.id);
  });

  it('returns the widget data selection and parameters', async () => {
    const { dataSelection, parameters } = await getWidgetArguments({} as any, 'my-dashboard', 'widget-1');

    expect(dataSelection).toEqual(['selection']);
    expect(parameters).toEqual({});
  });
});
