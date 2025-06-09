import React, { ReactNode, UIEvent, useState } from 'react';
import { PopoverProps } from '@mui/material/Popover/Popover';
import { MoreVert } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import Menu from '@mui/material/Menu';
import { useFormatter } from './i18n';
import stopEvent from '../utils/domEvent';

interface ChildrenProps {
  closeMenu: () => void
}

interface PopoverMenuProps {
  children: (props: ChildrenProps) => ReactNode
}

const PopoverMenu = ({ children }: PopoverMenuProps) => {
  const { t_i18n } = useFormatter();
  const [anchorPopover, setAnchorPopover] = useState<PopoverProps['anchorEl']>(null);

  const onOpenPopover = (event: UIEvent) => {
    stopEvent(event);
    setAnchorPopover(event.currentTarget);
  };

  const onClosePopover = (event: UIEvent) => {
    stopEvent(event);
    setAnchorPopover(null);
  };

  const closeMenu = () => setAnchorPopover(null);

  return (
    <>
      <ToggleButton
        onClick={onOpenPopover}
        aria-label={t_i18n('Popover of actions')}
        value="popover"
        aria-haspopup="true"
        size="small"
        color="primary"
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>
      <Menu
        anchorEl={anchorPopover}
        open={Boolean(anchorPopover)}
        onClose={onClosePopover}
        aria-label={t_i18n('Popover menu')}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {children({ closeMenu })}
      </Menu>
    </>
  );
};

export default PopoverMenu;
