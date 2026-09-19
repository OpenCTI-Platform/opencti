import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { FieldProps } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import StixCoreObjectFilesAndHistory, { stixCoreObjectFilesAndHistoryAskJobImportMutation } from './StixCoreObjectFilesAndHistory';
import { fileManagerCreateDraftAskJobImportMutation } from '../files/FileManager';

const { mockCommitMutation, mockNotifyError, mockNotifySuccess } = vi.hoisted(() => ({
  mockCommitMutation: vi.fn(),
  mockNotifyError: vi.fn(),
  mockNotifySuccess: vi.fn(),
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    createFragmentContainer: (component: React.ComponentType) => component,
  };
});

vi.mock('@mui/styles/withStyles', () => ({
  default: () => (Component: React.ComponentType<Record<string, unknown>>) => {
    const Wrapped = (props: Record<string, unknown>) => (
      <Component
        {...props}
        classes={{ container: '', gridContainer: '', paper: '' }}
      />
    );
    return Wrapped;
  },
}));

vi.mock('../../../../components/i18n', () => ({
  __esModule: true,
  default: (Component: React.ComponentType<object>) => Component,
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../../../../relay/environment', () => ({
  commitMutation: mockCommitMutation,
  handleError: vi.fn(),
  MESSAGING$: {
    notifyError: mockNotifyError,
    notifySuccess: mockNotifySuccess,
  },
}));

vi.mock('../files/FileManager', () => ({
  CONTENT_MAX_MARKINGS_HELPERTEXT: 'CONTENT_MAX_MARKINGS_HELPERTEXT',
  CONTENT_MAX_MARKINGS_TITLE: 'CONTENT_MAX_MARKINGS_TITLE',
  fileManagerCreateDraftAskJobImportMutation: { kind: 'mock-file-manager-create-draft' },
}));

vi.mock('@components/drafts/DraftCreation', () => ({
  DRAFTWORKSPACE_TYPE: 'DraftWorkspace',
}));

vi.mock('../../../../utils/hooks/useDraftContext', () => ({
  __esModule: true,
  default: vi.fn(() => ({ id: 'draft-context-1' })),
}));

vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../utils/hooks/useAuth')>();
  return {
    ...actual,
    __esModule: true,
    default: vi.fn(() => ({
      me: { id: 'me-1' },
      settings: {},
    })),
  };
});

vi.mock('../../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: vi.fn(() => ({ mandatoryAttributes: [] })),
}));

vi.mock('../../../../utils/hooks/useDefaultValues', () => ({
  __esModule: true,
  default: vi.fn(() => ({
    name: '',
    description: '',
    objectAssignee: [],
    objectParticipant: [],
    createdBy: undefined,
    authorized_members: undefined,
  })),
}));

vi.mock('../../../../utils/edition', () => ({
  convertMarkings: vi.fn(() => []),
}));

vi.mock('@common/dialog/Dialog', () => ({
  __esModule: true,
  default: ({ open, children }: { open: boolean; children: React.ReactNode }) => (open ? <div>{children}</div> : null),
}));

vi.mock('@common/button/Button', () => ({
  __esModule: true,
  default: ({ onClick, children, disabled }: { onClick?: () => void; children: React.ReactNode; disabled?: boolean }) => (
    <button type="button" onClick={onClick} disabled={disabled}>{children}</button>
  ),
}));

vi.mock('../../../../components/fields/SelectField', () => ({
  __esModule: true,
  default: ({
    field,
    form,
    children,
    name,
    label,
    onChange,
  }: FieldProps & {
    children: React.ReactNode;
    name: string;
    label: string;
    onChange?: (event: unknown, value: string) => void;
  }) => {
    const fieldName = name ?? field.name;
    const value = (form.values as Record<string, string>)[fieldName] ?? '';
    return (
      <label>
        {label}
        <select
          aria-label={label}
          value={value}
          onChange={(event) => {
            const nextValue = event.currentTarget.value;
            form.setFieldValue(fieldName, nextValue);
            onChange?.(event, nextValue);
          }}
        >
          <option value="" />
          {React.Children.map(children, (child) => {
            if (!React.isValidElement<{
              value: string;
              disabled?: boolean;
              children?: React.ReactNode;
            }>(child)) {
              return null;
            }
            return (
              <option value={child.props.value} disabled={child.props.disabled}>
                {child.props.children}
              </option>
            );
          })}
        </select>
      </label>
    );
  },
}));

vi.mock('../files/FileImportViewer', () => ({
  __esModule: true,
  default: ({ handleOpenImport }: { handleOpenImport: (file: { id: string; metaData: { mimetype: string } }) => void }) => (
    <button
      type="button"
      onClick={() => handleOpenImport({ id: 'file-1', metaData: { mimetype: 'application/json' } })}
    >
      Open import
    </button>
  ),
}));

vi.mock('../files/FileExportViewer', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../files/workbench/WorkbenchFileViewer', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../files/draftWorkspace/DraftWorkspaceViewer', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../files/FileExternalReferencesViewer', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('./StixCoreObjectHistory', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../../data/import/ManageImportConnectorMessage', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../form/ObjectMarkingField', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../form/AuthorizedMembersField', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('@components/common/form/ObjectAssigneeField', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('@components/common/form/ObjectParticipantField', () => ({
  __esModule: true,
  default: () => null,
}));

vi.mock('@components/common/form/CreatedByField', () => ({
  __esModule: true,
  default: () => null,
}));

describe('StixCoreObjectFilesAndHistory - import in draft context', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCommitMutation.mockImplementation(({ onCompleted }: { onCompleted?: () => void }) => {
      onCompleted?.();
    });
  });

  it('uses standard askJobImport mutation and does not raise an error toast', async () => {
    const { user } = testRender(
      <StixCoreObjectFilesAndHistory
        id="entity-1"
        entity={{ id: 'entity-1' }}
        connectorsExport={[]}
        connectorsImport={[
          {
            id: 'connector-1',
            name: 'ImportStix',
            active: true,
            only_contextual: false,
            connector_scope: ['application/json'],
            configurations: [],
          },
        ]}
      />,
    );

    await user.click(screen.getByRole('button', { name: 'Open import' }));
    await user.selectOptions(screen.getByLabelText('Connector'), 'connector-1');
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(mockCommitMutation).toHaveBeenCalled();
      expect(mockCommitMutation).toHaveBeenCalledWith(
        expect.objectContaining({
          mutation: stixCoreObjectFilesAndHistoryAskJobImportMutation,
        }),
      );
      expect(mockCommitMutation).toHaveBeenCalledWith(
        expect.not.objectContaining({
          mutation: fileManagerCreateDraftAskJobImportMutation,
        }),
      );
    });

    expect(mockNotifyError).not.toHaveBeenCalled();
  });
});
