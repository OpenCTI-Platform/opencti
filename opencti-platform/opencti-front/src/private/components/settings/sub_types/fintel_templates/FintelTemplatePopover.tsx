import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { MenuItem, Menu, PopoverProps, IconButton } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import stopEvent from '../../../../../utils/domEvent';

interface FintelTemplatePopoverProps {
  onUpdate: () => void
}

const FintelTemplatePopover = ({
  onUpdate,
}: FintelTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();

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

  return (
    <>
      <IconButton onClick={onOpenMenu} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
      </Menu>
    </>
  );
};

export default FintelTemplatePopover;
