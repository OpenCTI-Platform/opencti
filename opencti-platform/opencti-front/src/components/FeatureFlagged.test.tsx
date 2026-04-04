import { describe, it, expect, vi, afterEach } from 'vitest';
import { screen } from '@testing-library/react';
import FeatureFlagged from './FeatureFlagged';
import testRender from '../utils/tests/test-render';
import useHelper from '../utils/hooks/useHelper';
import type { ModuleHelper } from '../utils/platformModulesHelper';

vi.mock('../utils/hooks/useHelper');

describe('FeatureFlagged', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('renders Enabled when one of the flags is enabled', () => {
    vi.mocked(useHelper).mockReturnValue({
      isFeatureEnable: (flag: string) => flag === 'SOME_FLAG',
    } as unknown as ModuleHelper);
    testRender(
      <FeatureFlagged
        flags={['SOME_FLAG', 'SOME_OTHER_FLAG']}
        Enabled="Enabled"
        Disabled="Disabled"
      />,
    );
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('renders Disabled when none of the flags are enabled', () => {
    vi.mocked(useHelper).mockReturnValue({
      isFeatureEnable: () => false,
    } as unknown as ModuleHelper);
    testRender(
      <FeatureFlagged
        flags={['SOME_FLAG', 'SOME_OTHER_FLAG']}
        Enabled="Enabled"
        Disabled="Disabled"
      />,
    );
    expect(screen.getByText('Disabled')).toBeInTheDocument();
  });
});
