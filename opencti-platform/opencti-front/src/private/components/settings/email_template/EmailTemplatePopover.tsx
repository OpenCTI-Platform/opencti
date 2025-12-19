import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import IconButton from '@common/button/IconButton';
import useEmailTemplateDelete from '@components/settings/email_template/useEmailTemplateDelete';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import DeleteDialog from '../../../../components/DeleteDialog';

interface EmailTemplatePopoverProps {
  onUpdate: () => void;
  onDeleteComplete?: () => void;
  templateId: string;
  inline?: boolean;
}

const EmailTemplatePopover = ({
  onUpdate,
  onDeleteComplete,
  templateId,
  inline = true,
}: EmailTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [commitDeleteMutation] = useEmailTemplateDelete();

  const deletion = useDeletion({ handleClose: () => setAnchorEl(undefined) });
  const {
    handleOpenDelete,
    handleCloseDelete,
  } = deletion;

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  const update = (e: UIEvent) => {
    stopEvent(e);
    onUpdate();
    onCloseMenu(e);
  };

  const onDelete = (e: UIEvent) => {
    stopEvent(e);

    commitDeleteMutation({
      variables: { id: templateId },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      {inline ? (
        <IconButton onClick={onOpenMenu} aria-haspopup="true" color="primary">
          <MoreVert fontSize="small" />
        </IconButton>
      ) : (
        <IconButton
          onClick={onOpenMenu}
          aria-haspopup="true"
          className="icon-outlined"
          variant="secondary"
        >
          <MoreVert fontSize="small" />
        </IconButton>
      )}

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this email template?')}
      />
    </>
  );
};

export default EmailTemplatePopover;
