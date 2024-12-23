import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { MenuItem, Menu, PopoverProps, IconButton } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import useFintelTemplateDelete from '@components/settings/sub_types/fintel_templates/useFintelTemplateDelete';
import Transition from '../../../../../components/Transition';
import stopEvent from '../../../../../utils/domEvent';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';

interface FintelTemplatePopoverProps {
  onUpdate: () => void,
  entitySettingId: string,
  templateId: string,
}

const FintelTemplatePopover = ({
  onUpdate,
  entitySettingId,
  templateId,
}: FintelTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [commitDeleteMutation, deleting] = useFintelTemplateDelete(entitySettingId);

  const {
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
  } = useDeletion({});

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onHandleOpenDelete = (e: UIEvent) => {
    stopEvent(e);
    handleOpenDelete();
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  const onHandleCloseDelete = (e: UIEvent) => {
    stopEvent(e);
    handleCloseDelete();
    setAnchorEl(null);
  };

  const update = (e: UIEvent) => {
    stopEvent(e);
    onUpdate();
    onCloseMenu(e);
  };

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    if (!templateId) return;

    commitDeleteMutation(templateId, {
      variables: { id: templateId },
      onCompleted: () => {
        handleCloseDelete();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      <IconButton onClick={onOpenMenu} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={onHandleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        TransitionComponent={Transition}
        onClose={onHandleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this FINTEL template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={onHandleCloseDelete} disabled={deleting}>
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
