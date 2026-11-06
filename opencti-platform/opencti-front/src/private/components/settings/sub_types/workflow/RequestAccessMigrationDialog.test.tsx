import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import ThemeDark from '../../../../../components/ThemeDark';
import RequestAccessMigrationDialog from './RequestAccessMigrationDialog';

const testTheme = createTheme(ThemeDark() as ThemeOptions);

type Diagnostic = { type: string; message: string };

const diagnosticsOf = (diagnostics: Diagnostic[]) => ({
  workflowMigrationPreview: {
    entityType: 'Case-Rfi',
    results: [
      {
        scope: 'GLOBAL',
        initialState: 'tpl-global',
        hasPublishedVersion: false,
        states: [{ statusId: 'tpl-global', order: 0, requestAccessOutcome: null }],
        transitions: [],
        diagnostics: [],
      },
      {
        scope: 'REQUEST_ACCESS',
        initialState: 'tpl-new',
        hasPublishedVersion: false,
        states: [
          { statusId: 'tpl-validated', order: 1, requestAccessOutcome: 'APPROVED' },
          { statusId: 'tpl-new', order: 0, requestAccessOutcome: null },
          { statusId: 'tpl-refused', order: 2, requestAccessOutcome: 'DECLINED' },
        ],
        transitions: [
          { event: 'Accept', from: ['tpl-new'], to: 'tpl-validated' },
          { event: 'Reject', from: ['tpl-new'], to: 'tpl-refused' },
        ],
        diagnostics,
      },
    ],
  },
  statusTemplates: {
    edges: [
      { node: { id: 'tpl-new', name: 'Incoming' } },
      { node: { id: 'tpl-validated', name: 'Validated' } },
      { node: { id: 'tpl-refused', name: 'Refused' } },
    ],
  },
});

let mockPreview = diagnosticsOf([]);
const mockQuery = vi.fn();

vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    useLazyLoadQuery: (...args: unknown[]) => {
      mockQuery(...args);
      return mockPreview;
    },
  };
});

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../components/i18n')>(),
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

vi.mock('../../../Error', () => ({
  ErrorBoundary: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit, false],
}));

const onClose = vi.fn();
const onMigrated = vi.fn();

const renderDialog = () => render(
  <ThemeProvider theme={testTheme}>
    <RequestAccessMigrationDialog open onClose={onClose} onMigrated={onMigrated} />
  </ThemeProvider>,
);

const confirmButton = () => screen.getByTestId('request-access-migration-confirm-button');

describe('RequestAccessMigrationDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPreview = diagnosticsOf([]);
  });

  it('shows migration preview diagnostics for REQUEST_ACCESS', () => {
    mockPreview = diagnosticsOf([
      { type: 'DUPLICATE_ORDER', message: 'Two statuses share the same order' },
      { type: 'REQUEST_ACCESS_OUTCOME_INVALID', message: 'Approved and Declined statuses are the same' },
    ]);
    renderDialog();

    expect(mockQuery.mock.calls[0][1]).toEqual({ entityType: 'Case-Rfi' });

    const states = within(screen.getByTestId('request-access-migration-states'));
    const names = states.getAllByRole('listitem').map((item) => item.textContent);
    expect(names).toEqual(['Incoming', 'ValidatedApproved', 'RefusedDeclined']);

    const transitions = screen.getByTestId('request-access-migration-transitions');
    expect(transitions).toHaveTextContent('Accept: Incoming → Validated');
    expect(transitions).toHaveTextContent('Reject: Incoming → Refused');

    const [warning, blocking] = screen.getAllByTestId('request-access-migration-diagnostic');
    expect(warning).toHaveTextContent('Two statuses share the same order');
    expect(warning).toHaveTextContent('Warning');
    expect(blocking).toHaveTextContent('Approved and Declined statuses are the same');
    expect(blocking).toHaveTextContent('Blocking');
    expect(confirmButton()).toBeDisabled();
  });

  it('enables confirm when no blocking diagnostic remains', () => {
    mockPreview = diagnosticsOf([{ type: 'DUPLICATE_ORDER', message: 'Two statuses share the same order' }]);
    renderDialog();

    expect(confirmButton()).toBeEnabled();
  });

  it('only lets a name conflict block the migration while publishing', async () => {
    const user = userEvent.setup();
    mockPreview = diagnosticsOf([{ type: 'NAME_CONFLICT', message: 'Two statuses are named alike' }]);
    renderDialog();

    expect(confirmButton()).toBeDisabled();

    await user.click(screen.getByRole('switch', { name: 'Publish immediately' }));

    expect(confirmButton()).toBeEnabled();
  });

  it('confirm calls workflowMigrate with scope REQUEST_ACCESS and publish', async () => {
    const user = userEvent.setup();
    renderDialog();

    expect(screen.getByRole('switch', { name: 'Publish immediately' })).toBeChecked();
    await user.click(confirmButton());

    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(mockCommit).toHaveBeenCalledWith(expect.objectContaining({
      variables: { entityType: 'Case-Rfi', publish: true, overwrite: false, scope: 'REQUEST_ACCESS' },
    }));
    expect(onClose).not.toHaveBeenCalled();

    mockCommit.mock.calls[0][0].onCompleted({}, null);

    expect(onMigrated).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('migrates without publishing when the switch is turned off', async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(screen.getByRole('switch', { name: 'Publish immediately' }));
    await user.click(confirmButton());

    expect(mockCommit).toHaveBeenCalledWith(expect.objectContaining({
      variables: { entityType: 'Case-Rfi', publish: false, overwrite: false, scope: 'REQUEST_ACCESS' },
    }));
  });

  it('stays open when the migration fails', async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(confirmButton());
    mockCommit.mock.calls[0][0].onError(new Error('Cannot publish migrated workflow'));

    expect(onMigrated).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(confirmButton()).toBeEnabled();
  });

  it('cancel does nothing', async () => {
    const user = userEvent.setup();
    renderDialog();

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(mockCommit).not.toHaveBeenCalled();
    expect(onMigrated).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  describe('over a request access workflow never published', () => {
    const existingDraft = { type: 'EXISTING_WORKFLOW', message: 'Entity type already has a request access workflow with no published version' };
    const replaceCheckbox = () => screen.getByRole('checkbox', { name: 'Replace the current draft of the request access workflow' });

    it('asks to confirm the draft replacement before migrating', async () => {
      const user = userEvent.setup();
      mockPreview = diagnosticsOf([existingDraft]);
      renderDialog();

      expect(screen.getByTestId('request-access-migration-replace-draft')).toHaveTextContent('The current draft of the request access workflow will be replaced by the migrated statuses.');
      expect(screen.queryByText(existingDraft.message)).not.toBeInTheDocument();
      expect(confirmButton()).toBeDisabled();

      await user.click(replaceCheckbox());
      expect(confirmButton()).toBeEnabled();
      await user.click(confirmButton());

      expect(mockCommit).toHaveBeenCalledWith(expect.objectContaining({
        variables: { entityType: 'Case-Rfi', publish: true, overwrite: true, scope: 'REQUEST_ACCESS' },
      }));
    });

    it('keeps other blocking diagnostics blocking once the replacement is confirmed', async () => {
      const user = userEvent.setup();
      mockPreview = diagnosticsOf([existingDraft, { type: 'MISSING_TEMPLATE', message: 'A template is gone' }]);
      renderDialog();

      await user.click(replaceCheckbox());

      expect(confirmButton()).toBeDisabled();
    });

    it('cannot replace a published request access workflow', () => {
      mockPreview = diagnosticsOf([{ type: 'EXISTING_WORKFLOW', message: 'Entity type already has a published request access workflow' }]);
      mockPreview.workflowMigrationPreview.results[1].hasPublishedVersion = true;
      renderDialog();

      expect(screen.queryByTestId('request-access-migration-replace-draft')).not.toBeInTheDocument();
      expect(screen.getByTestId('request-access-migration-diagnostic')).toHaveTextContent('Blocking');
      expect(confirmButton()).toBeDisabled();
    });
  });

  it('has nothing to confirm when no request access status exists', () => {
    mockPreview = { ...diagnosticsOf([]) };
    mockPreview.workflowMigrationPreview.results = mockPreview.workflowMigrationPreview.results.filter((result) => result.scope === 'GLOBAL');
    renderDialog();

    expect(screen.getByText('There is no request access status to migrate.')).toBeInTheDocument();
    expect(screen.queryByTestId('request-access-migration-confirm-button')).not.toBeInTheDocument();
  });
});
