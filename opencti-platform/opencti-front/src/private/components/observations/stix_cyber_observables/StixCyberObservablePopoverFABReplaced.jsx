import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { useNavigate } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import { stixCyberObservableEditionQuery } from './StixCyberObservableEdition';
import StixCyberObservableEditionContainer from './StixCyberObservableEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Transition from '../../../../components/Transition';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';

const StixCyberObservablePopoverFABReplacedDeletionMutation = graphql`
  mutation StixCyberObservablePopoverFABReplacedDeletionMutation($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

const StixCyberObservablePopoverFABReplaced = ({ id }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEnroll, setDisplayEnroll] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: StixCyberObservablePopoverFABReplacedDeletionMutation,
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/observations/observables');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  const handleOpenEnroll = () => {
    setDisplayEnroll(true);
    handleClose();
  };
  const handleCloseEnroll = () => {
    setDisplayEnroll(false);
  };
  return isFABReplaced
    ? (<></>)
    : (
      <>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnroll}>
              {t_i18n('Enroll in playbook')}
            </MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrollPlaybook stixCoreObjectId={id} open={displayEnroll} handleClose={handleCloseEnroll} />
        <Dialog
          open={displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this observable?')}
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
        <Drawer
          title={t_i18n('Update an observable')}
          open={displayEdit}
          onClose={handleCloseEdit}
        >
          <QueryRenderer
            query={stixCyberObservableEditionQuery}
            variables={{ id }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCyberObservableEditionContainer
                    stixCyberObservable={props.stixCyberObservable}
                    handleClose={handleCloseEdit}
                    open={displayEdit}
                  />
                );
              }
              return <div />;
            }}
          />
        </Drawer>
      </>
    );
};

export default StixCyberObservablePopoverFABReplaced;
