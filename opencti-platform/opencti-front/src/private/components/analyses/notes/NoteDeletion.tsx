import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const NoteDeletionDeleteMutation = graphql`
  mutation NoteDeletionDeleteMutation($id: ID!) {
    noteEdit(id: $id) {
      delete
    }
  }
`;

interface NoteDeletionProps {
  id?: string;
  handleOpenRemoveExternal?: () => void;
  note?: StixCoreObjectOrStixCoreRelationshipNoteCard_node$data;
  paginationOptions?: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
}

const NoteDeletion: FunctionComponent<NoteDeletionProps> = ({
  id,
  handleOpenRemoveExternal,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Note') },
  });
  const [commit] = useApiMutation(
    NoteDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({});
  const { setDeleting, handleOpenDelete, handleCloseDelete, deleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_notes', paginationOptions, id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        if (handleOpenRemoveExternal) {
          handleCloseDelete();
        } else {
          navigate('/dashboard/analyses/notes');
        }
      },
    });
  };
  return (
    <>
      <Button
        color="error"
        variant="contained"
        onClick={handleOpenDelete}
        disabled={deleting}
        sx={{ marginTop: 2 }}
      >
        {t_i18n('Delete')}
      </Button>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this note?')}
      />
    </>
  );
};

export default NoteDeletion;
