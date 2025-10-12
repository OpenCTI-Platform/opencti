import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import SecurityCoverageDeletion from './SecurityCoverageDeletion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
  },
  dialogActions: {
    padding: '0 17px 20px 0',
  },
}));

const securityCoveragePopoverDeletionMutation = graphql`
  mutation SecurityCoveragePopoverDeletionMutation($id: ID!) {
    securityCoverageDelete(id: $id)
  }
`;

interface SecurityCoveragePopoverProps {
  id: string;
  handleOpen?: () => void;
  handleDelete?: () => void;
  disabled?: boolean;
}

const SecurityCoveragePopover: FunctionComponent<SecurityCoveragePopoverProps> = ({
  id,
  handleOpen,
  handleDelete,
  disabled,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayDeleteWithElements, setDisplayDeleteWithElements] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [commitMutation] = useApiMutation(securityCoveragePopoverDeletionMutation);

  const handleOpenMenu = (event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleCloseMenu = () => {
    setAnchorEl(null);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleCloseMenu();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const handleCloseDeleteWithElements = () => {
    setDisplayDeleteWithElements(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: {
        id,
      },
      updater: (store) => {
        if (handleDelete) {
          handleDelete();
        }
        deleteNode(store, 'Pagination__securityCoverages', {}, id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        if (window.location.pathname.includes(id)) {
          navigate('/dashboard/analyses/security_coverages');
        }
      },
    });
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpenMenu}
        aria-haspopup="true"
        disabled={disabled}
        size="large"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleCloseMenu}
      >
        <MenuItem
          onClick={() => {
            if (handleOpen) {
              handleOpen();
            } else {
              navigate(`/dashboard/analyses/security_coverages/${id}`);
            }
            handleCloseMenu();
          }}
        >
          {t_i18n('Open')}
        </MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>
            {t_i18n('Delete')}
          </MenuItem>
        </Security>
      </Menu>
      <SecurityCoverageDeletion
        id={id}
        isOpen={displayDelete}
        handleClose={handleCloseDelete}
      />
      <Dialog
        open={displayDeleteWithElements}
        onClose={handleCloseDeleteWithElements}
        PaperProps={{ elevation: 1 }}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this security coverage?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions classes={{ root: classes.dialogActions }}>
          <Button onClick={handleCloseDeleteWithElements} disabled={deleting}>
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

export default SecurityCoveragePopover;
