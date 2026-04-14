import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findPlaybooksForEntity } from '../../../../src/modules/playbook/playbook-domain';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as cache from '../../../../src/database/cache';
import * as middleware from '../../../../src/database/middleware';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as ee from '../../../../src/enterprise-edition/ee';
import { testContext } from '../../../utils/testQuery';

describe('Listen knowledge component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;
  const mockStixEntity = { id: 'malware--id' } as unknown as StixLoadReturn;

  const buildPlaybook = (configuration: object, playbookStart = 'node-1') => ({
    playbook_start: playbookStart,
    playbook_definition: JSON.stringify({
      nodes: [{
        id: playbookStart,
        component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
        configuration: JSON.stringify(configuration),
      }],
    }),
  } as unknown as BasicStoreEntityPlaybook);

  it('should return playbook when enrollInPlaybook is true and filters match', async () => {
    const playbook = buildPlaybook({ enrollInPlaybook: true });
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(1);
    expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
  });

  it('should exclude playbook when enrollInPlaybook is false', async () => {
    const playbook = buildPlaybook({ enrollInPlaybook: false });
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
    expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
  });

  it('should include playbook when enrollInPlaybook is undefined (legacy)', async () => {
    const playbook = buildPlaybook({});
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(1);
  });

  it('should exclude playbook when filters do not match', async () => {
    const playbook = buildPlaybook({ enrollInPlaybook: true });
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
  });
});
