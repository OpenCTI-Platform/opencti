import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildPlaybookNotRunnableError, findPlaybooksForEntity, PLAYBOOK_NOT_RUNNABLE_REASONS } from '../../../../src/modules/playbook/playbook-domain';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as cache from '../../../../src/database/cache';
import * as middleware from '../../../../src/database/middleware';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as ee from '../../../../src/enterprise-edition/ee';
import { testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';

const STATUS_FILTER = {
  mode: 'and',
  filters: [{ key: ['x_opencti_workflow_id'], values: ['status-validated'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const buildPlaybook = (componentId: string, configuration: object) => ({
  id: 'playbook-id',
  name: 'Validated reports',
  playbook_start: 'node-1',
  playbook_definition: JSON.stringify({
    nodes: [{ id: 'node-1', component_id: componentId, configuration: JSON.stringify(configuration) }],
  }),
} as unknown as BasicStoreEntityPlaybook);

type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;
const mockReport = { id: 'report--id', type: 'report' } as unknown as StixLoadReturn;

const extensionsOf = (error: unknown) => (error as { extensions: { code: string; data: Record<string, unknown> } }).extensions;

describe('buildPlaybookNotRunnableError', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
    vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockReport);
  });

  it('should say the playbook does not exist when its id is unknown', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([]);

    const error = await buildPlaybookNotRunnableError(testContext, SYSTEM_USER, 'unknown-id', 'report-id');
    expect(error.message).toBe('Playbook does not exist');
    const { code, data } = extensionsOf(error);
    expect(code).toBe('FUNCTIONAL_ERROR');
    expect(data.http_status).toBe(400);
    expect(data.reason).toBe(PLAYBOOK_NOT_RUNNABLE_REASONS.NOT_FOUND);
  });

  it('should name the filter mismatch and carry the entry filter when the entity does not match it', async () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true, filters: JSON.stringify(STATUS_FILTER) });
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

    // Same eligibility as before: the playbook is not offered for this entity
    expect(await findPlaybooksForEntity(testContext, SYSTEM_USER, 'report-id')).toHaveLength(0);

    const error = await buildPlaybookNotRunnableError(testContext, SYSTEM_USER, 'playbook-id', 'report-id');
    expect(error.message).toBe('Entity does not match the entry filter of playbook Validated reports');
    const { code, data } = extensionsOf(error);
    expect(code).toBe('FUNCTIONAL_ERROR');
    expect(data.http_status).toBe(400);
    expect(data).toMatchObject({
      id: 'playbook-id',
      entityId: 'report-id',
      reason: PLAYBOOK_NOT_RUNNABLE_REASONS.FILTER_MISMATCH,
      filters: STATUS_FILTER,
    });
  });

  it('should keep a matching entity eligible', async () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true, filters: JSON.stringify(STATUS_FILTER) });
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([playbook]);
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

    const result = await findPlaybooksForEntity(testContext, SYSTEM_USER, 'report-id');
    expect(result.map((p) => p.id)).toEqual(['playbook-id']);
  });

  it('should say manual enrollment is disabled', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false })]);

    const error = await buildPlaybookNotRunnableError(testContext, SYSTEM_USER, 'playbook-id', 'report-id');
    expect(error.message).toBe('Playbook Validated reports does not allow manual enrollment');
    expect(extensionsOf(error).data.reason).toBe(PLAYBOOK_NOT_RUNNABLE_REASONS.MANUAL_ENROLLMENT_DISABLED);
  });

  it('should name the entry component when it cannot be triggered manually', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_CRON', {})]);

    const error = await buildPlaybookNotRunnableError(testContext, SYSTEM_USER, 'playbook-id', 'report-id');
    expect(error.message).toBe('Playbook Validated reports cannot be run manually (its entry component is PLAYBOOK_INTERNAL_DATA_CRON)');
    expect(extensionsOf(error).data).toMatchObject({
      reason: PLAYBOOK_NOT_RUNNABLE_REASONS.ENTRY_COMPONENT_NOT_MANUAL,
      component: 'PLAYBOOK_INTERNAL_DATA_CRON',
    });
  });

  it('should say Enterprise Edition is required when it is not enabled', async () => {
    vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {})]);
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(false);

    const error = await buildPlaybookNotRunnableError(testContext, SYSTEM_USER, 'playbook-id', 'report-id');
    expect(extensionsOf(error).data.reason).toBe(PLAYBOOK_NOT_RUNNABLE_REASONS.ENTERPRISE_EDITION_REQUIRED);
  });
});
