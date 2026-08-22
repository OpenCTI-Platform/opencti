import React, { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ThemeProvider, createTheme, ThemeOptions } from '@mui/material/styles';
import GlobalWorkflowSettingsCard from './GlobalWorkflowSettingsCard';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import ThemeDark from '../../../../../components/ThemeDark';

const testTheme = createTheme(ThemeDark() as ThemeOptions);
const renderWithTheme = (component: React.ReactElement) => render(
  <ThemeProvider theme={testTheme}>
    {component}
  </ThemeProvider>,
);

vi.mock('@common/card/Card', () => ({
  default: ({ title, children }: { title: string; children: ReactNode }) => (
    <div>
      <h2>{title}</h2>
      {children}
    </div>
  ),
}));

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (value: string) => value,
  }),
}));

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: vi.fn(),
}));

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: vi.fn(),
}));

const mockIsFeatureEnable = vi.fn();
vi.mock('../../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: mockIsFeatureEnable }),
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit],
}));

vi.mock('./GlobalWorkflowSettings', () => ({
  default: () => <div>global-workflow-settings</div>,
}));

vi.mock('./RequestAccessSettings', () => ({
  default: () => <div>request-access-settings</div>,
}));

const makeSubType = (availableSettings: string[], syncWorkflowStatusByName = false) => ({
  id: 'sub-type-id',
  workflowEnabled: true,
  settings: {
    id: 'entity-setting-id',
    availableSettings,
    sync_workflow_status_by_name: syncWorkflowStatusByName,
    requestAccessConfiguration: { id: 'request-access-configuration-id' },
  },
});

describe('GlobalWorkflowSettingsCard', () => {
  beforeEach(() => {
    mockIsFeatureEnable.mockReturnValue(true);
  });

  afterEach(() => {
    mockCommit.mockReset();
    mockIsFeatureEnable.mockReset();
  });

  it('renders request access settings when request_access_workflow is available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_workflow']),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.getByText('request-access-settings')).toBeInTheDocument();
  });

  it('does not render request access settings when request_access_workflow is not available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_configuration']),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.queryByText('request-access-settings')).not.toBeInTheDocument();
  });

  it('does not render request access settings in CE even when request_access_workflow is available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_workflow']),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.queryByText('request-access-settings')).not.toBeInTheDocument();
  });

  it('disables the sync workflow status by name switch when not available for the entity type', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration']),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    expect(screen.getByRole('checkbox')).toBeDisabled();
  });

  it('toggles sync_workflow_status_by_name via the generic entitySettingsFieldPatch mutation', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'sync_workflow_status_by_name'], false),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    const switchInput = screen.getByRole('checkbox');
    expect(switchInput).not.toBeDisabled();
    expect(switchInput).not.toBeChecked();

    switchInput.click();

    expect(mockCommit).toHaveBeenCalledWith({
      variables: {
        ids: ['entity-setting-id'],
        input: { key: 'sync_workflow_status_by_name', value: 'true' },
      },
    });
  });

  it('does not render the sync workflow status by name switch when the feature flag is disabled', () => {
    mockIsFeatureEnable.mockReturnValue(false);
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'sync_workflow_status_by_name'], true),
    } as never);

    renderWithTheme(<GlobalWorkflowSettingsCard />);

    expect(screen.queryByText("Update entities' statuses by name match")).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});
