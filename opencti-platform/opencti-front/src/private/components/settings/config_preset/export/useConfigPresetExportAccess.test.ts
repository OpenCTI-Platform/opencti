import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import useGranted from '../../../../../utils/hooks/useGranted';
import useHelper from '../../../../../utils/hooks/useHelper';
import useConfigPresetExportAccess from './useConfigPresetExportAccess';

vi.mock('../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../utils/hooks/useGranted')>()),
  default: vi.fn(),
}));
vi.mock('../../../../../utils/hooks/useHelper', () => ({ default: vi.fn() }));

const mockAccess = (isBypass: boolean, enabledFlags: string[]) => {
  (useGranted as Mock).mockReturnValue(isBypass);
  (useHelper as Mock).mockReturnValue({ isFeatureEnable: (flag: string) => enabledFlags.includes(flag) });
};

describe('useConfigPresetExportAccess', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('grants the export to a BYPASS user when the flag is enabled', () => {
    mockAccess(true, ['CONFIG_PRESET']);
    expect(useConfigPresetExportAccess()).toBe(true);
    expect(useGranted).toHaveBeenCalledWith(['BYPASS']);
  });

  it('hides the export when the flag is disabled', () => {
    mockAccess(true, ['OTHER_FLAG']);
    expect(useConfigPresetExportAccess()).toBe(false);
  });

  it('hides the export from a user without BYPASS', () => {
    mockAccess(false, ['CONFIG_PRESET']);
    expect(useConfigPresetExportAccess()).toBe(false);
  });
});
