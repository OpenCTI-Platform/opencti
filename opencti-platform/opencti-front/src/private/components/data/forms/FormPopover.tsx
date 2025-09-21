import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const formPopoverDeletionMutation = graphql`
  mutation FormPopoverDeletionMutation($id: ID!) {
    formDelete(id: $id)
  }
`;

interface FormPopoverProps {
  formId: string;
  paginationOptions: FormLinesPaginationQuery$variables;
}

const FormPopover: FunctionComponent<FormPopoverProps> = ({
  formId,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleEdit = () => {
    navigate(`/dashboard/data/forms/${formId}/edit`);
    handleClose();
  };

  const handleDuplicate = () => {
    navigate(`/dashboard/data/forms/${formId}/duplicate`);
    handleClose();
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: formPopoverDeletionMutation,
      variables: {
        id: formId,
      },
      updater: (store: any) => {
        deleteNode(
          store,
          'Pagination_forms',
          paginationOptions,
          formId,
        );
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      onError: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      setSubmitting: setDeleting,
    } as any);
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="large"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleEdit}>
          {t_i18n('Edit')}
        </MenuItem>
        <MenuItem onClick={handleDuplicate}>
          {t_i18n('Duplicate')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this form?')}
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

export default FormPopover;
