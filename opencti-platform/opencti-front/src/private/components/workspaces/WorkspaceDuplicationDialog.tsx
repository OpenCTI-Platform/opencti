import React, { FunctionComponent, useMemo, useState } from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import TextField from '@mui/material/TextField';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import {
  WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation,
  WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation$data,
} from '@components/workspaces/__generated__/WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation.graphql';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../components/i18n';
import Transition from '../../../components/Transition';
import { handleError, MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';

// FIXME: code does not validate that the new name is different from existing name

interface WorkspaceDuplicationDialogProps {
  workspace: {
    name: string;
    type: string;
    description: string;
    manifest: string;
  };
  displayDuplicate: boolean;
  duplicating: boolean;
  handleCloseDuplicate: () => void;
  setDuplicating: (value: boolean) => void;
  updater?: (
    store: RecordSourceSelectorProxy<WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation$data>,
  ) => void;
  paginationOptions?: {
    search: string;
    orderBy: string;
    orderMode: string;
    filters: Array<{ key: string; values: Array<string> }>;
  };
}

const workspaceDuplicationDialogDuplicatedWorkspaceCreation = graphql`
  mutation WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation(
    $input: WorkspaceDuplicateInput!
  ) {
    workspaceDuplicate(input: $input) {
      id
      ...WorkspaceLine_node
    }
  }
`;
const WorkspaceDuplicationDialog: FunctionComponent<
WorkspaceDuplicationDialogProps
> = ({
  workspace,
  duplicating,
  setDuplicating,
  displayDuplicate,
  handleCloseDuplicate,
  updater,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const duplicatedDashboardInitialName = useMemo(
    () => `${workspace.name} - ${t_i18n('copy')}`,
    [t_i18n, workspace.name],
  );
  const [newName, setNewName] = useState(duplicatedDashboardInitialName);
  const [commitDuplicatedWorkspaceCreation] = useApiMutation<WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation>(
    workspaceDuplicationDialogDuplicatedWorkspaceCreation,
  );
  const submitDashboardDuplication = (submittedWorkspace: {
    name: string;
    type: string;
    description: string;
    manifest: string;
  }) => {
    commitDuplicatedWorkspaceCreation({
      variables: {
        input: {
          name: submittedWorkspace.name,
          type: submittedWorkspace.type,
          description: submittedWorkspace.description,
          manifest: submittedWorkspace.manifest,
        },
      },
      updater: (store) => updater && updater(store),
      onError: (error) => {
        handleError(error);
      },
      onCompleted: (data) => {
        handleCloseDuplicate();
        const isDashboardView = !paginationOptions;
        if (isDashboardView) {
          MESSAGING$.notifySuccess(
            <span>
              {t_i18n('The dashboard has been duplicated. You can manage it')}{' '}
              <Link
                to={`/dashboard/workspaces/dashboards/${data.workspaceDuplicate?.id}`}
              >
                {t_i18n('here')}
              </Link>
              .
            </span>,
          );
        }
      },
    });
  };
  const handleSubmitDuplicate = (submittedNewName: string) => {
    setDuplicating(true);
    submitDashboardDuplication({ ...workspace, name: submittedNewName });
  };
  return (
    <Dialog
      open={displayDuplicate}
      PaperProps={{ elevation: 1 }}
      TransitionComponent={Transition}
      onClose={handleCloseDuplicate}
      fullWidth={true}
      maxWidth="xs"
    >
      <DialogTitle>{t_i18n('Duplicate the dashboard')}</DialogTitle>
      <DialogContent>
        <TextField
          error={!newName}
          autoFocus
          margin="dense"
          id="duplicated_dashboard_name"
          label={t_i18n('New name')}
          type="text"
          fullWidth
          variant="standard"
          helperText={!newName ? `${t_i18n('This field is required')}` : ''}
          required={true}
          defaultValue={newName}
          onChange={(event) => {
            event.preventDefault();
            setNewName(event.target.value);
          }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCloseDuplicate}>{t_i18n('Cancel')}</Button>
        <Button
          color="secondary"
          onClick={() => handleSubmitDuplicate(newName)}
          disabled={duplicating || !newName}
        >
          {t_i18n('Duplicate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkspaceDuplicationDialog;
