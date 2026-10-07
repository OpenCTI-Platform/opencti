import { beforeEach, describe, expect, it, vi } from 'vitest';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { addPlatformProvidesFromLogsources } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(async () => undefined),
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
});
