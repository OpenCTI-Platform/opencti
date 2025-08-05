import React from 'react';
import { useNavigate } from 'react-router-dom';
import WorkspacePopoverDeletionMutation from '@components/workspaces/WorkspacePopoverDeletionMutation';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDeletion from '../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../components/DeleteDialog';

const WorkspaceDeletion = ({
  id,
  isOpen,
  handleClose,
  workspaceType,
}: {
  id: string,
  isOpen: boolean,
  handleClose: () => void,
  workspaceType: string | null | undefined
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Workspace') },
  });

  const [commit] = useApiMutation(
    WorkspacePopoverDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (workspaceType === 'investigation') {
          navigate('/dashboard/workspaces/investigations');
        } else {
          navigate('/dashboard/workspaces/dashboards');
        }
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={workspaceType === 'investigation'
        ? t_i18n('Do you want to delete this investigation?')
        : t_i18n('Do you want to delete this dashboard?')}
    />
  );
};

export default WorkspaceDeletion;
