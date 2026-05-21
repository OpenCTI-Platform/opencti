import React, { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import GlobalWorkflowSettingsCard from './GlobalWorkflowSettingsCard';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

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

vi.mock('./GlobalWorkflowSettings', () => ({
  default: () => <div>global-workflow-settings</div>,
}));

vi.mock('./RequestAccessSettings', () => ({
  default: () => <div>request-access-settings</div>,
}));

const makeSubType = (availableSettings: string[]) => ({
  id: 'sub-type-id',
  workflowEnabled: true,
  settings: {
    availableSettings,
    requestAccessConfiguration: { id: 'request-access-configuration-id' },
  },
});

describe('GlobalWorkflowSettingsCard', () => {
  it('renders request access settings when request_access_workflow is available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_workflow']),
    } as never);

    render(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.getByText('request-access-settings')).toBeInTheDocument();
  });

  it('does not render request access settings when request_access_workflow is not available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_configuration']),
    } as never);

    render(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.queryByText('request-access-settings')).not.toBeInTheDocument();
  });

  it('does not render request access settings in CE even when request_access_workflow is available', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    vi.mocked(useSubTypeOutletContext).mockReturnValue({
      subType: makeSubType(['workflow_configuration', 'request_access_workflow']),
    } as never);

    render(<GlobalWorkflowSettingsCard />);

    expect(screen.getByText('global-workflow-settings')).toBeInTheDocument();
    expect(screen.queryByText('request-access-settings')).not.toBeInTheDocument();
  });
});
