import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import useGranted from '../../../../../../utils/hooks/useGranted';
import useHelper from '../../../../../../utils/hooks/useHelper';
import useConfigPresetPartialImportAccess from './useConfigPresetPartialImportAccess';

vi.mock('../../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useGranted')>()),
  default: vi.fn(),
}));
vi.mock('../../../../../../utils/hooks/useHelper', () => ({ default: vi.fn() }));

const mockAccess = (isBypass: boolean, enabledFlags: string[]) => {
  (useGranted as Mock).mockReturnValue(isBypass);
  (useHelper as Mock).mockReturnValue({ isFeatureEnable: (flag: string) => enabledFlags.includes(flag) });
};

describe('useConfigPresetPartialImportAccess', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('grants the partial import to a BYPASS user when the CONFIG_PRESET flag is enabled', () => {
    mockAccess(true, ['CONFIG_PRESET']);
    expect(useConfigPresetPartialImportAccess()).toBe(true);
    expect(useGranted).toHaveBeenCalledWith(['BYPASS']);
  });

  it('refuses it when the flag is disabled, or to a user without BYPASS', () => {
    mockAccess(true, []);
    expect(useConfigPresetPartialImportAccess()).toBe(false);
    mockAccess(false, ['CONFIG_PRESET']);
    expect(useConfigPresetPartialImportAccess()).toBe(false);
  });
});
