import { describe, expect, it, vi, beforeEach } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import ImportFilesDialog from './ImportFilesDialog';

// ---------------------------------------------------------------------------
// Hoisted mocks – declared before vi.mock factories so they can be referenced
// ---------------------------------------------------------------------------
const {
  mockSetDraftId,
  mockSetUploadStatus,
  mockCommitCreationMutation,
  mockBulkCommit,
  mockEnterDraft,
  mockNotifyError,
  mockUseImportFilesContext,
} = vi.hoisted(() => ({
  mockSetDraftId: vi.fn(),
  mockSetUploadStatus: vi.fn(),
  mockCommitCreationMutation: vi.fn(),
  mockBulkCommit: vi.fn(),
  mockEnterDraft: vi.fn(),
  mockNotifyError: vi.fn(),
  mockUseImportFilesContext: vi.fn(),
}));

// ---------------------------------------------------------------------------
// AppIntlProvider – prevent createFragmentContainer from being called at
// module-load time (it lives at the top level of AppIntlProvider.tsx).
// We still wrap children in a real IntlProvider so that useIntl() / useFormatter()
// can find the required `intl` object in the component ancestry.
// ---------------------------------------------------------------------------
vi.mock('../../../../../components/AppIntlProvider', async () => {
  const { IntlProvider } = await import('react-intl');
  return {
    default: ({ children }: { children: React.ReactNode }) => React.createElement(IntlProvider, { locale: 'en', defaultLocale: 'en' }, children),
    ConnectedIntlProvider: ({ children }: { children: React.ReactNode }) => React.createElement(IntlProvider, { locale: 'en', defaultLocale: 'en' }, children),
  };
});

// ---------------------------------------------------------------------------
// Child component stubs (avoid rendering complex sub-trees)
// ---------------------------------------------------------------------------
vi.mock('@components/common/files/import_files/ImportFilesStepper', () => ({
  default: () => React.createElement('div', { 'data-testid': 'stepper' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesOptions', () => ({
  default: () => React.createElement('div', { 'data-testid': 'options' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesToggleMode', () => ({
  default: () => React.createElement('div', { 'data-testid': 'toggle-mode' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesFormSelector', () => ({
  default: () => React.createElement('div', { 'data-testid': 'form-selector' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesFormView', () => ({
  default: () => React.createElement('div', { 'data-testid': 'form-view' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesUploader', () => ({
  default: () => React.createElement('div', { 'data-testid': 'uploader' }),
}));
vi.mock('@components/common/files/import_files/ImportFilesUploadProgress', () => ({
  default: () => React.createElement('div', { 'data-testid': 'upload-progress' }),
}));

// ---------------------------------------------------------------------------
// ImportFilesContext – bypass Relay query loading
// ---------------------------------------------------------------------------
vi.mock('@components/common/files/import_files/ImportFilesContext', () => ({
  ImportFilesProvider: ({ children }: { children: React.ReactNode }) => children,
  useImportFilesContext: mockUseImportFilesContext,
  importFilesQuery: {},
}));

// ---------------------------------------------------------------------------
// useImportFilesData – mock the thin wrapper around usePreloadedQuery so we
// never need to mock 'react-relay' directly (which causes worker-startup
// hangs via vite-plugin-relay intercepting the module in Vitest's forks pool).
// ---------------------------------------------------------------------------
vi.mock('./useImportFilesData', () => ({
  default: vi.fn().mockReturnValue({
    stixCoreObject: null,
    connectorsForImport: [],
  }),
}));

// ---------------------------------------------------------------------------
// DraftCreation – prevent loading its heavy field-component imports
// (ObjectAssigneeField → StixDomainObjectDetectDuplicate →
//  StixDomainObjectsLines → createPaginationContainer from react-relay).
// ---------------------------------------------------------------------------
vi.mock('@components/drafts/DraftCreation', () => ({
  draftCreationMutation: {},
  DRAFTWORKSPACE_TYPE: 'DraftWorkspace',
}));

// ---------------------------------------------------------------------------
// useApiMutation – identify the draft-creation call via its errorMessage option
// ---------------------------------------------------------------------------
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: vi.fn().mockImplementation((_mutation: unknown, _fn: unknown, options: { errorMessage?: string } | undefined) => {
    if (options?.errorMessage) {
      // This is the DraftCreationMutation (it is the only call with errorMessage)
      return [mockCommitCreationMutation, false];
    }
    return [vi.fn(), false];
  }),
}));

// ---------------------------------------------------------------------------
// useSwitchDraft
// ---------------------------------------------------------------------------
vi.mock('../../../drafts/useSwitchDraft', () => ({
  default: vi.fn().mockReturnValue({
    enterDraft: mockEnterDraft,
    exitDraft: vi.fn(),
  }),
}));

// ---------------------------------------------------------------------------
// useBulkCommit – do nothing so we can isolate createDraft behaviour
// ---------------------------------------------------------------------------
vi.mock('../../../../../utils/hooks/useBulkCommit', () => ({
  default: vi.fn().mockReturnValue({
    bulkCommit: mockBulkCommit,
    bulkCount: 0,
    bulkCurrentCount: 0,
    BulkResult: () => null,
  }),
}));

// ---------------------------------------------------------------------------
// useDraftContext – no active draft
// ---------------------------------------------------------------------------
vi.mock('../../../../../utils/hooks/useDraftContext', () => ({
  default: vi.fn().mockReturnValue(null),
  DRAFT_TOOLBAR_HEIGHT: 69,
}));

// ---------------------------------------------------------------------------
// useIsMandatoryAttribute – no mandatory attributes → form always valid
// ---------------------------------------------------------------------------
vi.mock('../../../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: vi.fn().mockReturnValue({ mandatoryAttributes: [] }),
}));

// ---------------------------------------------------------------------------
// useDefaultValues – return minimal draft defaults
// ---------------------------------------------------------------------------
vi.mock('../../../../../utils/hooks/useDefaultValues', () => ({
  default: vi.fn().mockReturnValue({
    name: '',
    description: '',
    objectAssignee: [],
    objectParticipant: [],
    createdBy: undefined,
    authorized_members: undefined,
  }),
}));

// ---------------------------------------------------------------------------
// relay/environment – capture notifyError calls
// ---------------------------------------------------------------------------
vi.mock('../../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../../relay/environment')>();
  return {
    ...actual,
    MESSAGING$: {
      notifyError: mockNotifyError,
      notifySuccess: vi.fn(),
    },
    handleErrorInForm: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Default context values shared across tests
// ---------------------------------------------------------------------------
const defaultContextValues = {
  activeStep: 2,
  setActiveStep: vi.fn(),
  importMode: 'manual' as const,
  files: [{ file: new File(['content'], 'test.csv'), connectors: [] }],
  entityId: undefined,
  uploadStatus: undefined,
  setUploadStatus: mockSetUploadStatus,
  draftId: undefined,
  setDraftId: mockSetDraftId,
  inDraftContext: false,
  queryRef: {} as never,
  selectedFormId: undefined,
  canSelectImportMode: true,
  isForcedImportToDraft: false,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('ImportFilesDialog – createDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseImportFilesContext.mockReturnValue(defaultContextValues);
  });

  describe('when the draft mutation succeeds', () => {
    it('should call commitCreationMutation with the correct input variables', async () => {
      mockCommitCreationMutation.mockImplementation(
        ({ onCompleted }: { onCompleted: (r: unknown, e: null) => void }) => {
          onCompleted({ draftWorkspaceAdd: { id: 'draft-123' } }, null);
        },
      );

      const { user } = testRender(
        <ImportFilesDialog open={true} handleClose={vi.fn()} />,
      );

      await user.click(screen.getByRole('button', { name: 'Import' }));

      await waitFor(() => {
        expect(mockCommitCreationMutation).toHaveBeenCalledWith(
          expect.objectContaining({
            variables: {
              input: expect.objectContaining({
                name: '',
                description: '',
                entity_id: undefined,
                objectAssignee: [],
                objectParticipant: [],
                createdBy: undefined,
                authorized_members: null,
              }),
            },
          }),
        );
      });
    });

    it('should call setDraftId with the id returned by the mutation', async () => {
      mockCommitCreationMutation.mockImplementation(
        ({ onCompleted }: { onCompleted: (r: unknown, e: null) => void }) => {
          onCompleted({ draftWorkspaceAdd: { id: 'draft-123' } }, null);
        },
      );

      const { user } = testRender(
        <ImportFilesDialog open={true} handleClose={vi.fn()} />,
      );

      await user.click(screen.getByRole('button', { name: 'Import' }));

      await waitFor(() => {
        expect(mockSetDraftId).toHaveBeenCalledWith('draft-123');
      });
    });

    it('should pass entity_id when an entityId is set in the context', async () => {
      mockUseImportFilesContext.mockReturnValue({
        ...defaultContextValues,
        entityId: 'entity-456',
      });

      mockCommitCreationMutation.mockImplementation(
        ({ onCompleted }: { onCompleted: (r: unknown, e: null) => void }) => {
          onCompleted({ draftWorkspaceAdd: { id: 'draft-789' } }, null);
        },
      );

      const { user } = testRender(
        <ImportFilesDialog open={true} handleClose={vi.fn()} />,
      );

      await user.click(screen.getByRole('button', { name: 'Import' }));

      await waitFor(() => {
        expect(mockCommitCreationMutation).toHaveBeenCalledWith(
          expect.objectContaining({
            variables: {
              input: expect.objectContaining({
                entity_id: 'entity-456',
              }),
            },
          }),
        );
      });
    });

    it('should not call createDraft again when a draftId is already set in context', async () => {
      mockUseImportFilesContext.mockReturnValue({
        ...defaultContextValues,
        draftId: 'existing-draft-id',
      });

      const { user } = testRender(
        <ImportFilesDialog open={true} handleClose={vi.fn()} />,
      );

      await user.click(screen.getByRole('button', { name: 'Import' }));

      // bulkCommit should still be triggered but commitCreationMutation should NOT
      await waitFor(() => {
        expect(mockBulkCommit).toHaveBeenCalled();
      });
      expect(mockCommitCreationMutation).not.toHaveBeenCalled();
    });
  });
});
