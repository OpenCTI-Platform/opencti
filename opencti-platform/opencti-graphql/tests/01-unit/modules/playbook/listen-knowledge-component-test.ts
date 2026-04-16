import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findPlaybooksForEntity } from '../../../../src/modules/playbook/playbook-domain';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as cache from '../../../../src/database/cache';
import * as middleware from '../../../../src/database/middleware';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as ee from '../../../../src/enterprise-edition/ee';
import { testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';

describe('findPlaybooksForEntity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;
  const mockStixEntity = { id: 'malware--id' } as unknown as StixLoadReturn;

  const buildPlaybook = (componentId: string, configuration: object, playbookStart = 'node-1') => ({
    playbook_start: playbookStart,
    playbook_definition: JSON.stringify({
      nodes: [{
        id: playbookStart,
        component_id: componentId,
        configuration: JSON.stringify(configuration),
      }],
    }),
  } as unknown as BasicStoreEntityPlaybook);

  // -- Enterprise Edition --

  it('should return empty array when not EE', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(false);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(middleware.stixLoadById).not.toHaveBeenCalled;
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(cache.getEntitiesListFromCache).not.toHaveBeenCalled;
  });

  // -- Playbook Definition --

  it('should skip playbook when playbook_definition is missing', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([{ playbook_start: 'node-1', playbook_definition: null } as unknown as BasicStoreEntityPlaybook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
    expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
  });

  // -- Component ID --

  it('should skip playbook when component id is not PLAYBOOK_INTERNAL_DATA_STREAM or PLAYBOOK_INTERNAL_MANUAL_TRIGGER', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_OTHER_COMPONENT', {})]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
    expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
  });

  it('should include playbook with component PLAYBOOK_INTERNAL_DATA_STREAM when filters match', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true })]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(1);
  });

  it('should include playbook with component PLAYBOOK_INTERNAL_MANUAL_TRIGGER when filters match', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_MANUAL_TRIGGER', { canEnrollManually: true })]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(1);
  });

  // -- canEnrollManually --

  it('should exclude playbook when canEnrollManually is false', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false })]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
    expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
  });

  it('should include playbook when canEnrollManually is undefined', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {})]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(1);
  });

  // -- Filters --

  it('should exclude playbook when filters do not match', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true })]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(0);
  });

  it('should call isStixMatchFilterGroup with null when no filters are set', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true })]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalledWith(
      testContext, SYSTEM_USER, mockStixEntity, null,
    );
  });

  // -- Multiple Playbooks --

  it('should handle multiple playbooks and return only matching ones', async () => {
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockStixEntity);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false }),
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
    ]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, {} as any, 'entity-id');
    expect(result).toHaveLength(2);
  });
});
