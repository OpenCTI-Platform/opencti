import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';

const RegionDeletionDeleteMutation = graphql`
  mutation RegionDeletionDeleteMutation($id: ID!) {
    regionEdit(id: $id) {
      delete
    }
  }
`;

const RegionDeletion = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Region') },
  });
  const [commit] = useApiMutation(
    RegionDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleClose = () => {};
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/regions');
      },
    });
  };

  return (
    <div style={{ margin: 0 }}>
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
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this region?')}
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
    </div>
  );
};

export default RegionDeletion;
