import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import IconButton from '@common/button/IconButton';
import useFintelTemplateExport from './useFintelTemplateExport';
import useFintelTemplateDelete from './useFintelTemplateDelete';
import useFintelTemplateSetDefault from './useFintelTemplateSetDefault';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import stopEvent from '../../../../../utils/domEvent';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';

interface FintelTemplatePopoverProps {
  onUpdate: () => void;
  onDeleteComplete?: () => void;
  entitySettingId: string;
  templateId: string;
  settingsType: string;
  inline?: boolean;
  isDefault: boolean;
}

const FintelTemplatePopover = ({
  onUpdate,
  onDeleteComplete,
  entitySettingId,
  templateId,
  settingsType,
  inline = true,
  isDefault,
}: FintelTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const exportFintel = useFintelTemplateExport();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [commitDeleteMutation] = useFintelTemplateDelete(entitySettingId);
  const [commitSetDefault] = useFintelTemplateSetDefault();
  const [commitEditMutation] = useFintelTemplateEdit();

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
    if (!templateId) return;

    commitDeleteMutation(templateId, {
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

  const onExport = async (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    await exportFintel(templateId);
  };

  const onSetAsDefault = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    commitSetDefault({
      variables: { id: templateId, settingsType },
    });
  };

  const onSetRemoveDefault = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    commitEditMutation({
      variables: {
        id: templateId,
        input: [{ key: 'default', value: ['false'] }],
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
          size="default"
        >
          <MoreVert fontSize="small" />
        </IconButton>
      )}

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        <MenuItem onClick={onExport}>{t_i18n('Export')}</MenuItem>
        {isDefault
          ? <MenuItem onClick={onSetRemoveDefault}>{t_i18n('Remove default')}</MenuItem>
          : <MenuItem onClick={onSetAsDefault}>{t_i18n('Set as default')}</MenuItem>
        }
      </Menu>

      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this FINTEL template?')}
      />
    </>
  );
};

export default FintelTemplatePopover;
