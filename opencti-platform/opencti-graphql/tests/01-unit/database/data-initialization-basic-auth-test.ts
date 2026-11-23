import { describe, expect, it, vi } from 'vitest';
import { addSettings } from '../../../src/domain/settings';
import { initializeData } from '../../../src/database/data-initialization';
import type { AuthContext } from '../../../src/types/user';

// Stops initializeData right after it has built the settings of the new platform
const { SENTINEL } = vi.hoisted(() => ({ SENTINEL: new Error('stop after addSettings') }));

vi.mock('../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../src/modules/theme/theme-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/theme/theme-domain')>()),
  initDefaultTheme: vi.fn().mockResolvedValue({ id: 'dark-theme-id' }),
}));
vi.mock('../../../src/domain/settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/domain/settings')>()),
  addSettings: vi.fn().mockRejectedValue(SENTINEL),
}));

describe('initializeData, API Basic authentication', () => {
  it('should start a new platform with the API Basic authentication disabled', async () => {
    await expect(initializeData({} as AuthContext)).rejects.toBe(SENTINEL);
    expect(vi.mocked(addSettings)).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({ api_basic_auth_enabled: false }));
  });
});
