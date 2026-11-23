import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import ThemeDark from '../../../../../components/ThemeDark';
import RequestAccessOutcomeRepair from './RequestAccessOutcomeRepair';

type Template = { id: string; name: string; color: string };
let mockConfiguration: {
  approved_status: { template: Template } | null;
  declined_status: { template: Template } | null;
  approval_admin: { id: string; name: string }[];
} | null = null;

vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    useFragment: vi.fn(() => mockConfiguration),
  };
});

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: () => ({
    subType: { settings: { requestAccessConfiguration: { id: 'request-access-configuration' } } },
  }),
}));

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../components/i18n')>(),
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit],
}));

// The real field searches templates through the network: the stub only shows the value the form holds.
vi.mock('./StatusTemplateFieldScoped', () => ({
  default: ({ name, label, scope, setFieldValue }: {
    name: string;
    label: string;
    scope: string;
    setFieldValue: (field: string, value: unknown) => void;
  }) => (
    <div data-testid={`field-${name}`} data-scope={scope}>
      <span>{label}</span>
      <button type="button" onClick={() => setFieldValue(name, { label: 'Fixed', value: 'tpl-fixed', color: '#000' })}>{`pick ${name}`}</button>
    </div>
  ),
}));

const onRepaired = vi.fn();
const testTheme = createTheme(ThemeDark() as ThemeOptions);

const renderRepair = (initialState = 'tpl-open') => render(
  <ThemeProvider theme={testTheme}>
    <RequestAccessOutcomeRepair initialState={initialState} onRepaired={onRepaired} />
  </ThemeProvider>,
);

const saveButton = () => screen.getByTestId('request-access-outcome-repair-save-button');

describe('RequestAccessOutcomeRepair', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfiguration = {
      approved_status: { template: { id: 'tpl-validated', name: 'Validated', color: '#0f0' } },
      declined_status: { template: { id: 'tpl-validated', name: 'Validated', color: '#0f0' } },
      approval_admin: [{ id: 'group-soc', name: 'SOC' }],
    };
  });

  it('explains how to fix an outcome on the initial state instead of offering the form, which cannot fix it', () => {
    mockConfiguration = {
      approved_status: { template: { id: 'tpl-approved', name: 'Approved', color: '#0f0' } },
      declined_status: { template: { id: 'tpl-declined', name: 'Declined', color: '#f00' } },
      approval_admin: [],
    };
    renderRepair('tpl-approved');

    expect(screen.getByTestId('request-access-outcome-initial-state')).toBeInTheDocument();
    expect(screen.queryByTestId('request-access-outcome-repair')).not.toBeInTheDocument();
  });

  it('offers both outcome statuses of the request access scope', () => {
    renderRepair();

    expect(screen.getByTestId('field-approvedTemplate')).toHaveAttribute('data-scope', 'REQUEST_ACCESS');
    expect(screen.getByTestId('field-declinedTemplate')).toHaveAttribute('data-scope', 'REQUEST_ACCESS');
  });

  it('sends both statuses and keeps the validator group', async () => {
    const user = userEvent.setup();
    renderRepair();

    await user.click(screen.getByText('pick declinedTemplate'));
    await user.click(saveButton());

    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(mockCommit.mock.calls[0][0].variables).toEqual({
      input: {
        approved_status_id: 'tpl-validated',
        declined_status_id: 'tpl-fixed',
        approval_admin: ['group-soc'],
      },
    });
  });

  it('asks the dialog to read the preview again once saved', async () => {
    const user = userEvent.setup();
    renderRepair();

    await user.click(saveButton());
    mockCommit.mock.calls[0][0].onCompleted({}, undefined);

    expect(onRepaired).toHaveBeenCalledTimes(1);
  });

  it('does not ask for a new preview when the save returns errors', async () => {
    const user = userEvent.setup();
    renderRepair();

    await user.click(saveButton());
    mockCommit.mock.calls[0][0].onCompleted({}, [{ message: 'failed' }]);

    expect(onRepaired).not.toHaveBeenCalled();
  });

  it('cannot save while an outcome status is empty', async () => {
    const user = userEvent.setup();
    mockConfiguration = { approved_status: null, declined_status: null, approval_admin: [] };
    renderRepair();

    expect(saveButton()).toBeDisabled();

    await user.click(screen.getByText('pick approvedTemplate'));
    expect(saveButton()).toBeDisabled();

    await user.click(screen.getByText('pick declinedTemplate'));
    await waitFor(() => expect(saveButton()).toBeEnabled());
  });
});
