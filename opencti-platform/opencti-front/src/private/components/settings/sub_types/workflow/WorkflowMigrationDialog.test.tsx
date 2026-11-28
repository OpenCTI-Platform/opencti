import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import ThemeDark from '../../../../../components/ThemeDark';
import WorkflowMigrationDialog from './WorkflowMigrationDialog';

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

vi.mock('./RequestAccessOutcomeRepair', () => ({
  default: ({ onRepaired }: { onRepaired: () => void }) => (
    <button data-testid="outcome-repair" onClick={onRepaired}>repair</button>
  ),
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit, false],
}));

const onClose = vi.fn();
const onMigrated = vi.fn();

const renderDialog = (scope: 'GLOBAL' | 'REQUEST_ACCESS' = 'REQUEST_ACCESS', entityType = 'Case-Rfi') => render(
  <ThemeProvider theme={testTheme}>
    <WorkflowMigrationDialog entityType={entityType} scope={scope} open onClose={onClose} onMigrated={onMigrated} />
  </ThemeProvider>,
);

const confirmButton = () => screen.getByTestId('workflow-migration-confirm-button');

describe('WorkflowMigrationDialog', () => {
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

    const states = within(screen.getByTestId('workflow-migration-states'));
    const names = states.getAllByRole('listitem').map((item) => item.textContent);
    expect(names).toEqual(['Incoming', 'ValidatedApproved', 'RefusedDeclined']);

    const transitions = screen.getByTestId('workflow-migration-transitions');
    expect(transitions).toHaveTextContent('Accept: Incoming → Validated');
    expect(transitions).toHaveTextContent('Reject: Incoming → Refused');

    const [warning, blocking] = screen.getAllByTestId('workflow-migration-diagnostic');
    expect(warning).toHaveTextContent('Two statuses share the same order');
    expect(warning).toHaveTextContent('Warning');
    expect(blocking).toHaveTextContent('Approved and Declined statuses are the same');
    expect(blocking).toHaveTextContent('Blocking');
    expect(confirmButton()).toBeDisabled();
  });

  it('offers the outcome repair only when the outcome statuses are invalid', () => {
    mockPreview = diagnosticsOf([{ type: 'DUPLICATE_ORDER', message: 'Two statuses share the same order' }]);
    const { unmount } = renderDialog();
    expect(screen.queryByTestId('outcome-repair')).not.toBeInTheDocument();
    unmount();

    mockPreview = diagnosticsOf([{ type: 'REQUEST_ACCESS_OUTCOME_INVALID', message: 'Approved and Declined statuses are the same' }]);
    renderDialog();
    expect(screen.getByTestId('outcome-repair')).toBeInTheDocument();
  });

  it('reads the preview again once the outcome statuses are repaired', async () => {
    const user = userEvent.setup();
    mockPreview = diagnosticsOf([{ type: 'REQUEST_ACCESS_OUTCOME_INVALID', message: 'Approved and Declined statuses are the same' }]);
    renderDialog();
    expect(mockQuery.mock.calls.at(-1)?.[2]).toEqual({ fetchPolicy: 'network-only', fetchKey: 0 });

    await user.click(screen.getByTestId('outcome-repair'));

    expect(mockQuery.mock.calls.at(-1)?.[2]).toEqual({ fetchPolicy: 'network-only', fetchKey: 1 });
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

      expect(screen.getByTestId('workflow-migration-replace-draft')).toHaveTextContent('The current draft of the request access workflow will be replaced by the migrated statuses.');
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

      expect(screen.queryByTestId('workflow-migration-replace-draft')).not.toBeInTheDocument();
      expect(screen.getByTestId('workflow-migration-diagnostic')).toHaveTextContent('Blocking');
      expect(confirmButton()).toBeDisabled();
    });
  });

  it('has nothing to confirm when no request access status exists', () => {
    mockPreview = { ...diagnosticsOf([]) };
    mockPreview.workflowMigrationPreview.results = mockPreview.workflowMigrationPreview.results.filter((result) => result.scope === 'GLOBAL');
    renderDialog();

    expect(screen.getByText('There is no request access status to migrate.')).toBeInTheDocument();
    expect(screen.queryByTestId('workflow-migration-confirm-button')).not.toBeInTheDocument();
  });

  describe('on the Global scope', () => {
    it('previews the statuses of the entity type with the Global texts', () => {
      renderDialog('GLOBAL', 'Report');

      expect(mockQuery.mock.calls[0][1]).toEqual({ entityType: 'Report' });
      expect(screen.getByText('Migrate statuses')).toBeInTheDocument();
      expect(screen.getByText('The legacy statuses become a workflow. Existing statuses are reused, so entities keep their current status.')).toBeInTheDocument();
      const names = within(screen.getByTestId('workflow-migration-states')).getAllByRole('listitem').map((item) => item.textContent);
      expect(names).toEqual(['tpl-global']);
    });

    it('confirm calls workflowMigrate with scope GLOBAL on the entity type', async () => {
      const user = userEvent.setup();
      renderDialog('GLOBAL', 'Report');

      await user.click(confirmButton());

      expect(mockCommit).toHaveBeenCalledWith(expect.objectContaining({
        variables: { entityType: 'Report', publish: true, overwrite: false, scope: 'GLOBAL' },
      }));
    });

    it('asks to confirm the replacement of a Global draft', () => {
      mockPreview = diagnosticsOf([]);
      mockPreview.workflowMigrationPreview.results[0].diagnostics = [{ type: 'EXISTING_WORKFLOW', message: 'Entity type already has a workflow with no published version' }];
      renderDialog('GLOBAL', 'Report');

      expect(screen.getByTestId('workflow-migration-replace-draft')).toHaveTextContent('The current draft of the workflow will be replaced by the migrated statuses.');
      expect(screen.getByRole('checkbox', { name: 'Replace the current draft of the workflow' })).toBeInTheDocument();
      expect(confirmButton()).toBeDisabled();
    });

    it('has nothing to confirm when the entity type has no status', () => {
      mockPreview.workflowMigrationPreview.results = mockPreview.workflowMigrationPreview.results.filter((result) => result.scope === 'REQUEST_ACCESS');
      renderDialog('GLOBAL', 'Report');

      expect(screen.getByText('There is no status to migrate.')).toBeInTheDocument();
      expect(screen.queryByTestId('workflow-migration-confirm-button')).not.toBeInTheDocument();
    });
  });
});
