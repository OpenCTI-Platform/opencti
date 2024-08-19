import React, { FunctionComponent, useState } from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Note') },
  });
  const [commit] = useApiMutation(
    NoteDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
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
    <React.Fragment>
      <Button
        color="error"
        variant="contained"
        onClick={handleOpenDelete}
        disabled={deleting}
        sx={{ marginTop: 2 }}
      >
        {t_i18n('Delete')}
      </Button>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this note?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default NoteDeletion;
