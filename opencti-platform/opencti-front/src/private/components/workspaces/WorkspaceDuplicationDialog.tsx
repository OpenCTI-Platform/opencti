import React, { FunctionComponent, UIEvent, useMemo, useState } from 'react';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import TextField from '@mui/material/TextField';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import {
  WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation,
  WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation$data,
} from './__generated__/WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation.graphql';
import { WorkspaceDuplicationDialogFragment$data, WorkspaceDuplicationDialogFragment$key } from './__generated__/WorkspaceDuplicationDialogFragment.graphql';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';
import { useFormatter } from '../../../components/i18n';
import Transition from '../../../components/Transition';
import { handleError, MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import stopEvent from '../../../utils/domEvent';

const workspaceDuplicationFragment = graphql`
  fragment WorkspaceDuplicationDialogFragment on Workspace {
    name
    type
    description
    manifest
  }
`;

interface WorkspaceDuplicationDialogProps {
  data: WorkspaceDuplicationDialogFragment$key;
  displayDuplicate: boolean;
  duplicating: boolean;
  handleCloseDuplicate: () => void;
  setDuplicating: (value: boolean) => void;
  updater?: (
    store: RecordSourceSelectorProxy<WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation$data>,
  ) => void;
  paginationOptions?: WorkspacesLinesPaginationQuery$variables;
}

const workspaceDuplicationDialogDuplicatedWorkspaceCreation = graphql`
  mutation WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation(
    $input: WorkspaceDuplicateInput!
  ) {
    workspaceDuplicate(input: $input) {
      id
      ...WorkspacesLine_node
    }
  }
`;
const WorkspaceDuplicationDialog: FunctionComponent<
  WorkspaceDuplicationDialogProps
> = ({
  data,
  duplicating,
  setDuplicating,
  displayDuplicate,
  handleCloseDuplicate,
  updater,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const workspace = useFragment(workspaceDuplicationFragment, data);

  const duplicatedDashboardInitialName = useMemo(
    () => `${workspace.name} - ${t_i18n('copy')}`,
    [t_i18n, workspace.name],
  );
  const [newName, setNewName] = useState(duplicatedDashboardInitialName);
  const [commitDuplicatedWorkspaceCreation] = useApiMutation<WorkspaceDuplicationDialogDuplicatedWorkspaceCreationMutation>(
    workspaceDuplicationDialogDuplicatedWorkspaceCreation,
  );
  const submitDashboardDuplication = (
    e: UIEvent,
    submittedWorkspace: WorkspaceDuplicationDialogFragment$data,
  ) => {
    stopEvent(e);
    commitDuplicatedWorkspaceCreation({
      variables: {
        input: {
          name: submittedWorkspace.name,
          type: submittedWorkspace.type ?? '',
          description: submittedWorkspace.description ?? '',
          manifest: submittedWorkspace.manifest ?? '',
        },
      },
      updater: (store) => updater && updater(store),
      onError: (error) => {
        handleError(error);
      },
      onCompleted: (result) => {
        handleCloseDuplicate();
        const isDashboardView = !paginationOptions;
        if (isDashboardView) {
          MESSAGING$.notifySuccess(
            <span>
              {t_i18n('The dashboard has been duplicated. You can manage it')}{' '}
              <Link
                to={`/dashboard/workspaces/dashboards/${result.workspaceDuplicate?.id}`}
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

  const handleSubmitDuplicate = (e: UIEvent, submittedNewName: string) => {
    setDuplicating(true);
    submitDashboardDuplication(e, { ...workspace, name: submittedNewName });
  };

  return (
    <Dialog
      open={displayDuplicate}
      slotProps={{
        paper: {
          elevation: 1,
          onClick: (e: React.MouseEvent) => stopEvent(e),
        },
      }}
      slots={{ transition: Transition }}
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
          defaultValue={newName}
          onChange={(event) => {
            event.preventDefault();
            setNewName(event.target.value);
          }}
        />
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={() => handleCloseDuplicate()}>{t_i18n('Cancel')}</Button>
        <Button
          onClick={(e) => handleSubmitDuplicate(e, newName)}
          disabled={duplicating || !newName}
        >
          {t_i18n('Duplicate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkspaceDuplicationDialog;
