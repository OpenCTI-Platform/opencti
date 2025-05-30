import React, { UIEvent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import Button from '@mui/material/Button';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import stopEvent from '../../../utils/domEvent';

interface PirPopoverProps {
  handleOpenDelete: (e?: UIEvent) => void
  deleting: boolean
}

const PirPopover = ({
  handleOpenDelete,
  deleting,
}: PirPopoverProps) => {
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

  return (
    <>
      <Button
        onClick={onOpenMenu}
        aria-haspopup="true"
        className="icon-outlined"
        variant="outlined"
      >
        <MoreVert fontSize="small" />
      </Button>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={handleOpenDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
    </>
  );
};

export default PirPopover;
