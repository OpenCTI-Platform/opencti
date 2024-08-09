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

const groupingPopoverDeletionMutation = graphql`
  mutation GroupingPopoverDeletionMutation($id: ID!) {
    groupingDelete(id: $id)
  }
`;

interface GroupingPopoverDeletionProps {
  groupingId: string;
  displayDelete: boolean;
  handleClose: () => void;
  handleCloseDelete: () => void;
  handleOpenDelete: () => void;
}
const GroupingPopoverDeletion: FunctionComponent<GroupingPopoverDeletionProps> = ({
  groupingId,
  displayDelete,
  handleClose,
  handleCloseDelete,
  handleOpenDelete,
}) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [deleting, setDeleting] = useState(false);
  const [commitMutation] = useApiMutation(groupingPopoverDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: groupingId },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/analyses/groupings');
      },
    });
  };
  return (
    <React.Fragment>
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
    </React.Fragment>
  );
};

export default GroupingPopoverDeletion;
