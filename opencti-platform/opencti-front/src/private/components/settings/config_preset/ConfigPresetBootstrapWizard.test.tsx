import React from 'react';
import { act, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import useGranted from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ConfigPresetBootstrapWizard from './ConfigPresetBootstrapWizard';
import { RootSettings$data } from '../../../__generated__/RootSettings.graphql';

vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useGranted')>()),
  default: vi.fn(),
}));
vi.mock('../../../../utils/hooks/useHelper', () => ({ default: vi.fn() }));

const pendingSettings = { platform_bootstrap_status: 'pending', platform_bootstrap_wizard_enabled: true } as unknown as RootSettings$data;

const renderWizard = (settings = pendingSettings, skipped: boolean | null = null) => testRender(
  <ConfigPresetBootstrapWizard settings={settings} />,
  { userContext: createMockUserContext({ me: { bootstrap_wizard_skipped: skipped } }) },
);

describe('ConfigPresetBootstrapWizard', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    (useGranted as Mock).mockReturnValue(true);
    (useHelper as Mock).mockReturnValue({ isFeatureEnable: (flag: string) => flag === 'CONFIG_PRESET' });
  });

  it('opens by itself for a BYPASS user on a pending platform', () => {
    renderWizard();
    expect(screen.getByText('Set up your platform')).toBeInTheDocument();
  });

  it('never opens for a user without BYPASS', () => {
    (useGranted as Mock).mockReturnValue(false);
    renderWizard();
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
  });

  it('does not open when the status is completed, whatever the skip', () => {
    renderWizard({ ...pendingSettings, platform_bootstrap_status: 'completed' });
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
  });

  it('does not open on an existing platform, with the flag off or with the option off', () => {
    renderWizard({ ...pendingSettings, platform_bootstrap_status: null });
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
    (useHelper as Mock).mockReturnValue({ isFeatureEnable: () => false });
    renderWizard();
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
    (useHelper as Mock).mockReturnValue({ isFeatureEnable: () => true });
    renderWizard({ ...pendingSettings, platform_bootstrap_wizard_enabled: false });
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
  });

  it('does not open when the user skipped it', () => {
    renderWizard(pendingSettings, true);
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
  });

  it('stays open when the store changes after the first render', () => {
    const { rerender } = renderWizard();
    rerender(<ConfigPresetBootstrapWizard settings={{ ...pendingSettings, platform_bootstrap_status: 'completed' }} />);
    expect(screen.getByText('Set up your platform')).toBeInTheDocument();
  });

  it('closes on Skip and stores the skip', async () => {
    const { user, relayEnv } = renderWizard();
    await user.click(screen.getByRole('button', { name: 'Skip' }));
    expect(screen.queryByText('Set up your platform')).not.toBeInTheDocument();
    await act(async () => {
      expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    });
  });
});
