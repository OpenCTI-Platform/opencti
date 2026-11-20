import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { isEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { stixLoadByFilters } from '../../../../src/database/middleware';
import { playbookExecutor } from '../../../../src/manager/playbookManager/playbookExecutor';
import { handlePlaybookCrons } from '../../../../src/manager/playbookManager/playbookManager';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  isEnterpriseEdition: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  stixLoadByFilters: vi.fn(),
}));

vi.mock('../../../../src/utils/filtering/filtering-resolution', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/filtering/filtering-resolution')>(),
  convertFiltersToQueryOptions: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/utils/filtering/filtering-utils', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/utils/filtering/filtering-utils')>(),
  convertRelationRefsFilterKeys: vi.fn((filters) => filters),
}));

vi.mock('../../../../src/manager/playbookManager/playbookExecutor', () => ({
  playbookExecutor: vi.fn(async () => {}),
}));

const cronDefinition = JSON.stringify({
  nodes: [{
    id: 'start-node',
    name: 'Cron start',
    component_id: 'PLAYBOOK_INTERNAL_DATA_CRON',
    configuration: JSON.stringify({ period: 'minute', triggerTime: '', onlyLast: false, includeAll: true, filters: '{}' }),
  }],
  links: [],
});

const buildPlaybook = (id: string, definition: string) => ({
  id,
  internal_id: id,
  name: `playbook ${id}`,
  playbook_start: 'start-node',
  playbook_definition: definition,
} as unknown as BasicStoreEntityPlaybook);

describe('Playbook manager cron handler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
    vi.mocked(stixLoadByFilters).mockResolvedValue([{ id: 'indicator--00000000-0000-4000-8000-000000000001' }] as never);
  });

  it('keeps iterating over playbooks when one playbook_definition is malformed', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      buildPlaybook('malformed-playbook', '{ not a valid json'),
      buildPlaybook('valid-playbook', cronDefinition),
    ] as never);

    await expect(handlePlaybookCrons({} as AuthContext)).resolves.toBeUndefined();

    expect(playbookExecutor).toHaveBeenCalledTimes(1);
    expect(vi.mocked(playbookExecutor).mock.calls[0][0]).toMatchObject({ playbookId: 'valid-playbook' });
  });
});
