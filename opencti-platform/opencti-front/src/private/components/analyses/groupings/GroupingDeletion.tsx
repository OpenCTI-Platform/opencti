import React, { FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const GroupingDeletionDeleteMutation = graphql`
  mutation GroupingDeletionDeleteMutation($id: ID!) {
    groupingDelete(id: $id)
  }
`;

interface GroupingDeletionProps {
  groupingId: string;
  handleClose?: () => void;
}

const GroupingDeletion: FunctionComponent<GroupingDeletionProps> = ({
  groupingId,
  handleClose,
}) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Grouping') },
  });
  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };
  const [commitMutation] = useApiMutation(
    GroupingDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleCloseDelete = () => {
    setDeleting(false);
    setDisplayDelete(false);
  };
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: groupingId },
      onCompleted: () => {
        setDeleting(false);
        if (typeof handleClose === 'function') handleClose();
        navigate('/dashboard/analyses/groupings');
      },
    });
  };

  return (
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this grouping?')}
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
    </>
  );
};

export default GroupingDeletion;
