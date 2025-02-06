import React from 'react';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import { CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const taskDeletionDeleteMutation = graphql`
  mutation TaskDeletionDeleteMutation($id: ID!) {
    taskDelete(id: $id)
  }
`;

const TaskDeletion = ({
  id,
  objectId,
  paginationOptions,
}: {
  id: string;
  objectId?: string;
  paginationOptions?: CaseTasksLinesQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Task') },
  });
  const [commit] = useApiMutation(
    taskDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleClose = () => {};
  const deletion = useDeletion({ handleClose });
  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_tasks', paginationOptions, id);
        }
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
        if (objectId) {
          deletion.handleCloseDelete();
        } else {
          navigate('/dashboard/cases/tasks');
        }
      },
    });
  };

  return (
    <div style={{ margin: 0 }}>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={deletion.handleOpenDelete}
          disabled={deletion.deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this task?')}
      />
    </div>
  );
};

export default TaskDeletion;
