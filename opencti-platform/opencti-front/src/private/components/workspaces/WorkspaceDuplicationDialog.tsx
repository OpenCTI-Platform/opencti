import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import { FunctionComponent, UIEvent, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../relay/environment';
import stopEvent from '../../../utils/domEvent';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import {
  WorkspaceDuplicationDialogWorkspaceDuplicateMutation,
  WorkspaceDuplicationDialogWorkspaceDuplicateMutation$data,
} from './__generated__/WorkspaceDuplicationDialogWorkspaceDuplicateMutation.graphql';
import { WorkspaceDuplicationDialogFragment$data, WorkspaceDuplicationDialogFragment$key } from './__generated__/WorkspaceDuplicationDialogFragment.graphql';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';
import { Input } from '@filigran/design-system';

const workspaceDuplicationFragment = graphql`
  fragment WorkspaceDuplicationDialogFragment on Workspace {
    id
    name
    type
  }
`;

interface WorkspaceDuplicationDialogProps {
  data: WorkspaceDuplicationDialogFragment$key;
  displayDuplicate: boolean;
  duplicating: boolean;
  handleCloseDuplicate: () => void;
  setDuplicating: (value: boolean) => void;
  updater?: (
    store: RecordSourceSelectorProxy<WorkspaceDuplicationDialogWorkspaceDuplicateMutation$data>,
  ) => void;
  paginationOptions?: WorkspacesLinesPaginationQuery$variables;
}

const duplicateWorkspaceMutation = graphql`
  mutation WorkspaceDuplicationDialogWorkspaceDuplicateMutation(
    $id: ID!
    $name: String!
  ) {
    workspaceDuplicate(input: { id: $id, name: $name }) {
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
  const isInvestigation = workspace.type === 'investigation';

  const duplicatedWorkspaceInitialName = useMemo(
    () => `${workspace.name} - ${t_i18n('copy')}`,
    [t_i18n, workspace.name],
  );
  const [newName, setNewName] = useState(duplicatedWorkspaceInitialName);
  const wasDisplayed = useRef(false);

  useEffect(() => {
    if (displayDuplicate && !wasDisplayed.current) {
      setNewName(duplicatedWorkspaceInitialName);
    }
    wasDisplayed.current = displayDuplicate;
  }, [displayDuplicate, duplicatedWorkspaceInitialName]);

  const [commitDuplicateWorkspace] = useApiMutation<WorkspaceDuplicationDialogWorkspaceDuplicateMutation>(duplicateWorkspaceMutation);
  const submitWorkspaceDuplication = (
    e: UIEvent,
    submittedWorkspace: WorkspaceDuplicationDialogFragment$data,
  ) => {
    stopEvent(e);
    if (!['dashboard', 'investigation'].includes(submittedWorkspace.type ?? '')) {
      setDuplicating(false);
      return;
    }
    commitDuplicateWorkspace({
      variables: {
        id: submittedWorkspace.id,
        name: submittedWorkspace.name,
      },
      updater,
      onError: (error) => {
        handleError(error);
        setDuplicating(false);
      },
      onCompleted: (result) => {
        handleCloseDuplicate();
        setDuplicating(false);
        const isDashboardView = !paginationOptions;
        if (isDashboardView) {
          const duplicatedWorkspace = result.workspaceDuplicate;
          const workspaceType = isInvestigation ? 'investigations' : 'dashboards';
          MESSAGING$.notifySuccess(
            <span>
              {isInvestigation
                ? t_i18n('The investigation has been duplicated. You can manage it')
                : t_i18n('The dashboard has been duplicated. You can manage it')}{' '}
              <Link
                to={`/dashboard/workspaces/${workspaceType}/${duplicatedWorkspace?.id}`}
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
    submitWorkspaceDuplication(e, { ...workspace, name: submittedNewName });
  };

  return (
    <Dialog
      open={displayDuplicate}
      onClose={handleCloseDuplicate}
      fullWidth={true}
      title={isInvestigation ? t_i18n('Duplicate the investigation') : t_i18n('Duplicate the dashboard')}
    >
      <Input
        error={!newName ? t_i18n('This field is required') : undefined}
        autoFocus
        id="duplicated_workspace_name"
        label={t_i18n('New name')}
        type="text"
        value={newName}
        onChange={(event) => {
          event.preventDefault();
          setNewName(event.target.value);
        }}
      />
      <DialogActions>
        <Button variant="secondary" onClick={() => handleCloseDuplicate()}>{t_i18n('Cancel')}</Button>
        <Button
          onClick={(e) => handleSubmitDuplicate(e, newName)}
          disabled={duplicating || !newName || !['dashboard', 'investigation'].includes(workspace.type ?? '')}
        >
          {t_i18n('Duplicate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkspaceDuplicationDialog;
