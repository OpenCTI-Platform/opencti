import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
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
  isOpen,
  handleClose,
  objectId,
  paginationOptions,
}: {
  id: string;
  isOpen: boolean;
  handleClose: () => void;
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
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
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
        setDeleting(false);
        handleClose();
        if (objectId) {
          handleCloseDelete();
        } else {
          navigate('/dashboard/cases/tasks');
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
      message={t_i18n('Do you want to delete this task?')}
    />
  );
};

export default TaskDeletion;
