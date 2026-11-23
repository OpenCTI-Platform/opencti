import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TooltipProvider } from '@filigran/design-system';
import EntityStatusSyncSetting from './EntityStatusSyncSetting';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: vi.fn(),
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit],
}));

const mockSubType = (availableSettings: string[], syncWorkflowStatusByName: boolean | null) => {
  vi.mocked(useSubTypeOutletContext).mockReturnValue({
    subType: {
      id: 'Report',
      settings: {
        id: 'entity-setting-id',
        availableSettings,
        sync_workflow_status_by_name: syncWorkflowStatusByName,
      },
    },
  } as never);
};

// The library tooltip throws outside a `TooltipProvider`; the app mounts one in `private/Index.tsx`.
const renderSetting = () => render(<TooltipProvider><EntityStatusSyncSetting /></TooltipProvider>);

describe('EntityStatusSyncSetting', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('mirrors the stored setting', () => {
    mockSubType(['sync_workflow_status_by_name'], true);
    renderSetting();

    const toggle = screen.getByRole('switch', { name: 'Entity status sync' });
    expect(toggle).toBeChecked();
    expect(toggle).toBeEnabled();
  });

  it('is disabled when the entity type does not support it', () => {
    mockSubType(['workflow_configuration'], null);
    renderSetting();

    const toggle = screen.getByRole('switch', { name: 'Entity status sync' });
    expect(toggle).toBeDisabled();
    expect(toggle).not.toBeChecked();
  });

  it('commits the flipped value on click', () => {
    mockSubType(['sync_workflow_status_by_name'], false);
    renderSetting();

    screen.getByRole('switch', { name: 'Entity status sync' }).click();

    expect(mockCommit).toHaveBeenCalledWith({
      variables: {
        ids: ['entity-setting-id'],
        input: { key: 'sync_workflow_status_by_name', value: 'true' },
      },
    });
  });
});
