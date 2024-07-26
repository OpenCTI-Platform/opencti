import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import Transition from '../../../../components/Transition';
import CityEditionContainer, { cityEditionQuery } from './CityEditionContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const CityPopoverDeletionMutation = graphql`
  mutation CityPopoverDeletionMutation($id: ID!) {
    cityEdit(id: $id) {
      delete
    }
  }
`;

const CityPopover = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(CityPopoverDeletionMutation);
  const queryRef = useQueryLoading<CityEditionContainerQuery>(
    cityEditionQuery,
    { id },
    );
    const handleClose = () => {
      setAnchorEl(undefined);
    };
    const handleCloseEdit = () => {
      setDisplayEdit(false);
    };
    const {
      deleting,
      handleOpenDelete,
      displayDelete,
      handleCloseDelete,
      setDeleting,
    } = useDeletion({ handleClose });
    const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/cities');
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
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this city?')}
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
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <CityEditionContainer
            queryRef={queryRef}
            handleClose={handleCloseEdit}
            open={displayEdit}
          />
        </React.Suspense>
      )}
    </React.Fragment>
  );
};

export default CityPopover;
