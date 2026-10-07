import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, fullRelationsList, storeLoadById } from '../../../../src/database/middleware-loader';
import { addStixCoreRelationship } from '../../../../src/domain/stixCoreRelationship';
import { addPlatformProvidesFromLogsources, exportDefenseGaps } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { listAllDefenseLogsourceMappings } from '../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(async () => undefined),
  fullEntitiesList: vi.fn(async () => []),
  fullRelationsList: vi.fn(async () => []),
  internalFindByIds: vi.fn(async () => []),
}));
vi.mock('../../../../src/domain/stixCoreRelationship', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/stixCoreRelationship')>()),
  addStixCoreRelationship: vi.fn(async () => ({})),
}));
vi.mock('../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain')>()),
  listAllDefenseLogsourceMappings: vi.fn(async () => []),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;

describe('Defense telemetry from log sources', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it.each(['category', 'product', 'service'])('should refuse a %s longer than 256 characters before reading anything', async (field) => {
    const logsources = [{ product: 'windows' }, { [field]: ` ${'x'.repeat(257)} ` }];
    await expect(addPlatformProvidesFromLogsources(context, user, 'platform-id', logsources))
      .rejects.toThrow('A log source value cannot be longer than 256 characters');
    expect(vi.mocked(storeLoadById)).not.toHaveBeenCalled();
  });

  it('should accept a value of 256 characters once trimmed', async () => {
    // The platform lookup is the first read: reaching it means the values passed the bound
    await expect(addPlatformProvidesFromLogsources(context, user, 'platform-id', [{ service: ` ${'x'.repeat(256)} ` }]))
      .rejects.toThrow('Security platform or system not found');
    expect(vi.mocked(storeLoadById)).toHaveBeenCalledTimes(1);
  });

  it.each([
    [true, 1, 0],
    [false, 0, 1],
  ])('should declare again a revoked declaration (revoked: %s)', async (revoked, created, existing) => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ internal_id: 'platform-1' } as never);
    vi.mocked(listAllDefenseLogsourceMappings).mockResolvedValueOnce([{ active: true, x_opencti_rule_logsource: { product: 'windows' }, data_components: ['Process Creation'] }] as never);
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ internal_id: 'dc-1', name: 'Process Creation' }] as never);
    vi.mocked(fullRelationsList).mockResolvedValueOnce([{ id: 'provides-1', fromId: 'platform-1', toId: 'dc-1', revoked }] as never);
    const result = await addPlatformProvidesFromLogsources(context, user, 'platform-1', [{ product: 'windows' }]);
    expect(result.created_count).toEqual(created);
    expect(result.existing_count).toEqual(existing);
    if (revoked) {
      // The upsert of the same relationship sets revoked back to false
      expect(vi.mocked(addStixCoreRelationship)).toHaveBeenCalledWith(context, user, expect.objectContaining({
        fromId: 'platform-1',
        toId: 'dc-1',
        relationship_type: 'provides',
        revoked: false,
      }));
    } else {
      expect(vi.mocked(addStixCoreRelationship)).not.toHaveBeenCalled();
    }
  });
});

describe('Defense gaps export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should refuse the export without the web interface export capability', async () => {
    const reader = { capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser;
    await expect(exportDefenseGaps(context, reader, {})).rejects.toThrow('You are not allowed to do this.');
    expect(vi.mocked(fullEntitiesList)).not.toHaveBeenCalled();
  });
});
