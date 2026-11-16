import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import RequestAccessDrawerButton from './RequestAccessDrawerButton';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: vi.fn(),
}));

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: vi.fn(),
}));

vi.mock('@components/common/drawer/Drawer', () => ({
  default: ({ open, title, children }: { open: boolean; title: string; children: React.ReactNode }) => (
    open ? <div role="dialog" aria-label={title}>{children}</div> : null
  ),
}));

vi.mock('./RequestAccessSettings', () => ({
  default: () => <div>request access settings</div>,
}));

const mockSubType = (availableSettings: string[], hasConfiguration: boolean) => {
  vi.mocked(useSubTypeOutletContext).mockReturnValue({
    subType: {
      id: 'Case-Rfi',
      settings: {
        id: 'entity-setting-id',
        availableSettings,
        requestAccessConfiguration: hasConfiguration ? { id: 'configuration-id' } : null,
      },
    },
  } as never);
};

const BUTTON_NAME = 'Request access workflow';

describe('RequestAccessDrawerButton', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is hidden without the Enterprise Edition', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(false);
    mockSubType(['request_access_workflow'], true);
    render(<RequestAccessDrawerButton />);

    expect(screen.queryByRole('button', { name: BUTTON_NAME })).not.toBeInTheDocument();
  });

  it('is hidden when the entity type does not support request access', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    mockSubType(['workflow_configuration'], true);
    render(<RequestAccessDrawerButton />);

    expect(screen.queryByRole('button', { name: BUTTON_NAME })).not.toBeInTheDocument();
  });

  it('opens the request access settings in a drawer', () => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
    mockSubType(['request_access_workflow'], true);
    render(<RequestAccessDrawerButton />);

    expect(screen.queryByText('request access settings')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: BUTTON_NAME }));

    expect(screen.getByRole('dialog', { name: BUTTON_NAME })).toHaveTextContent('request access settings');
  });
});
