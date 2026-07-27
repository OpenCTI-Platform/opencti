import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findPlaybooksForEnrollment, findPlaybooksForEnrollmentByFilters, findPlaybooksForEntity } from '../../../../src/modules/playbook/playbook-domain';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as cache from '../../../../src/database/cache';
import * as middleware from '../../../../src/database/middleware';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as ee from '../../../../src/enterprise-edition/ee';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { emptyFilterGroup } from '../../../../src/utils/filtering/filtering-utils';

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

const buildStixEntity = (internalId: string) => ({
  id: `malware--${internalId}`,
  type: 'malware',
  spec_version: '2.1',
  extensions: { [STIX_EXT_OCTI]: { id: internalId } },
});

describe('findPlaybooksForEntity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;
  const mockStixEntity = { id: 'malware--id' } as unknown as StixLoadReturn;

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

describe('findPlaybooksForEnrollment', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    vi.spyOn(middleware, 'stixLoadByIds').mockResolvedValue([]);
  });

  // -- Enterprise Edition --

  it('should throw when not EE', async () => {
    vi.spyOn(ee, 'checkEnterpriseEdition').mockRejectedValue(new Error('Enterprise edition required'));
    const cacheSpy = vi.spyOn(cache, 'getEntitiesListFromCache');

    await expect(findPlaybooksForEnrollment(testContext, SYSTEM_USER, [])).rejects.toThrow('Enterprise edition required');
    expect(cacheSpy).not.toHaveBeenCalled();
  });

  // -- Playbook Definition --

  it('should skip playbook when playbook_definition is missing', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      { playbook_start: 'node-1', playbook_definition: null } as unknown as BasicStoreEntityPlaybook,
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(0);
  });

  // -- Component ID --

  it('should skip playbook when component_id is not PLAYBOOK_INTERNAL_DATA_STREAM or PLAYBOOK_INTERNAL_MANUAL_TRIGGER', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_OTHER_COMPONENT', {}),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(0);
  });

  it('should include playbook with component PLAYBOOK_INTERNAL_DATA_STREAM', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(1);
  });

  it('should include playbook with component PLAYBOOK_INTERNAL_MANUAL_TRIGGER', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_MANUAL_TRIGGER', { canEnrollManually: true }),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(1);
  });

  // -- canEnrollManually --

  it('should exclude playbook when canEnrollManually is false', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false }),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(0);
  });

  it('should include playbook when canEnrollManually is undefined (defaults to true)', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {}),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(1);
  });

  // -- Multiple Playbooks --

  it('should handle multiple playbooks and return only eligible ones', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false }),
      buildPlaybook('PLAYBOOK_INTERNAL_MANUAL_TRIGGER', {}),
      buildPlaybook('PLAYBOOK_OTHER_COMPONENT', { canEnrollManually: true }),
    ]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(2);
  });

  it('should return empty array when no playbooks exist', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([]);

    const result = await findPlaybooksForEnrollment(testContext, SYSTEM_USER, []);
    expect(result).toHaveLength(0);
  });

  it('should not load entities when no eligible playbooks', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([]);
    const stixLoadSpy = vi.spyOn(middleware, 'stixLoadByIds');

    await findPlaybooksForEnrollment(testContext, SYSTEM_USER, ['some-id']);

    expect(stixLoadSpy).not.toHaveBeenCalled();
  });
});

describe('findPlaybooksForEnrollmentByFilters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue(undefined);
  });

  it('should throw when not EE', async () => {
    vi.spyOn(ee, 'checkEnterpriseEdition').mockRejectedValue(new Error('Enterprise edition required'));

    await expect(findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []))
      .rejects.toThrow('Enterprise edition required');
  });

  it('should return empty and skip DB load when there are no eligible playbooks', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([]);
    const stixLoadByFiltersSpy = vi.spyOn(middleware, 'stixLoadByFilters');

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []);

    expect(result).toHaveLength(0);
    expect(stixLoadByFiltersSpy).not.toHaveBeenCalled();
  });

  it('should return empty and skip DB load when no playbook has canEnrollManually enabled', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false }),
    ]);
    const stixLoadByFiltersSpy = vi.spyOn(middleware, 'stixLoadByFilters');

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []);

    expect(result).toHaveLength(0);
    expect(stixLoadByFiltersSpy).not.toHaveBeenCalled();
  });

  it('should return empty when all entities are excluded', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
    ]);
    vi.spyOn(middleware, 'stixLoadByFilters').mockResolvedValue([
      buildStixEntity('id-1'),
      buildStixEntity('id-2'),
    ] as never);

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, ['id-1', 'id-2']);

    expect(result).toHaveLength(0);
  });

  it('should return playbook when it has no filters and entity is not excluded', async () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true });
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(middleware, 'stixLoadByFilters').mockResolvedValue([buildStixEntity('id-1')] as never);
    const isStixMatchFilterGroupSpy = vi.spyOn(stixFiltering, 'isStixMatchFilterGroup');

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []);

    expect(result).toEqual([playbook]);
    expect(isStixMatchFilterGroupSpy).not.toHaveBeenCalled();
  });

  it('should return matching playbooks when entity passes playbook filters', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
    ]);
    vi.spyOn(middleware, 'stixLoadByFilters').mockResolvedValue([buildStixEntity('id-1')] as never);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []);

    expect(result).toHaveLength(1);
  });

  it('should return empty when entity does not pass playbook filters', async () => {
    const filters = JSON.stringify(emptyFilterGroup);
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true, filters }),
    ]);
    vi.spyOn(middleware, 'stixLoadByFilters').mockResolvedValue([buildStixEntity('id-1')] as never);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

    const result = await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, null, null, []);

    expect(result).toHaveLength(0);
  });

  it('should pass filters and search to stixLoadByFilters', async () => {
    const filters = emptyFilterGroup;
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
      buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true }),
    ]);
    const stixLoadByFiltersSpy = vi.spyOn(middleware, 'stixLoadByFilters').mockResolvedValue([]);

    await findPlaybooksForEnrollmentByFilters(testContext, SYSTEM_USER, filters as never, 'my-search', []);

    expect(stixLoadByFiltersSpy).toHaveBeenCalledWith(
      testContext,
      SYSTEM_USER,
      expect.any(Array),
      expect.objectContaining({ filters, search: 'my-search' }),
    );
  });
});
