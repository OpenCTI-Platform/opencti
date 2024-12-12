import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { MenuItem, Menu, PopoverProps, IconButton } from '@mui/material';
import { graphql, UseMutationConfig } from 'react-relay';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { FintelTemplatePopoverDeleteMutation } from './__generated__/FintelTemplatePopoverDeleteMutation.graphql';
import Transition from '../../../../../components/Transition';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import stopEvent from '../../../../../utils/domEvent';

const fintelTemplatePopoverDeleteMutation = graphql`
  mutation FintelTemplatePopoverDeleteMutation($id: ID!) {
    fintelTemplateDelete(id: $id)
  }
`;

interface FintelTemplatePopoverProps {
  templateId: string
  onUpdate: () => void
  deleteUpdater?: UseMutationConfig<FintelTemplatePopoverDeleteMutation>['updater']
}

const FintelTemplatePopover = ({
  templateId,
  onUpdate,
  deleteUpdater,
}: FintelTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();

  const [commitDeleteMutation] = useApiMutation<FintelTemplatePopoverDeleteMutation>(fintelTemplatePopoverDeleteMutation);

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({});

  const onAskDelete = (e: UIEvent) => {
    stopEvent(e);
    handleOpenDelete();
    onCloseMenu(e);
  };

  const onCloseDelete = (e: UIEvent) => {
    stopEvent(e);
    handleCloseDelete();
  };

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    setDeleting(true);
    commitDeleteMutation({
      variables: { id: templateId },
      updater: deleteUpdater,
      onCompleted: () => {
        setDeleting(false);
        onCloseDelete(e);
      },
      onError: () => {
        setDeleting(false);
        onCloseDelete(e);
      },
    });
  };

  const update = (e: UIEvent) => {
    stopEvent(e);
    onUpdate();
    onCloseMenu(e);
  };

  return (
    <>
      <IconButton onClick={onOpenMenu} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={onAskDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={onCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this FINTEL template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={onCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={onDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default FintelTemplatePopover;
