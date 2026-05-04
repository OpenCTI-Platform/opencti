import { MouseEvent, ReactElement, useState } from 'react';
import { Box, type MenuItemProps, type PopoverProps, MenuItem } from '@mui/material';
import Tab, { TabProps } from '@mui/material/Tab';
import Menu from '@mui/material/Menu';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';

export const useDropDownMenuState = () => {
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);

  const onOpen = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorEl(event.currentTarget);
  };

  const onClose = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorEl(null);
  };

  const close = () => {
    setAnchorEl(null);
  };

  return { anchorEl, onOpen, onClose, isOpen: Boolean(anchorEl), close };
};

type TabWithDropDownMenuProps = Omit<TabProps<'div'>, 'onClick'> & {
  isOpen: boolean;
  onOpen: (event: MouseEvent) => void;
};

/** A Tab that shows an arrow indicator and triggers a drop-down menu on click. */
export const TabWithDropDownMenu = ({ isOpen, onOpen, label, ...tabProps }: TabWithDropDownMenuProps) => (
  <Tab
    {...tabProps}
    component="div"
    sx={{
      display: 'flex',
      flexDirection: 'row',
      gap: '4px',
      alignItems: 'center',
      // Compensate invalid vertical alignment of other tabs due to application
      // of 'inline-block' & 'textTransform'. To be removed if/when we find a
      // better way to capitalize first letters of all tabs.
      paddingBottom: '14px',
      paddingTop: '7px',
      // Compensate horizontal space in ArrowDropUp/ArrowDropDown svg
      paddingLeft: '19px',
      paddingRight: '13px',
    }}
    label={(
      <>
        <Box
          sx={{
            textTransform: 'lowercase',
            display: 'inline-block',
            '&::first-letter': {
              textTransform: 'uppercase',
            },
          }}
        >
          {label}
        </Box>
        {isOpen ? <ArrowDropUp sx={{ fontSize: '20px' }} /> : <ArrowDropDown sx={{ fontSize: '20px' }} />}
      </>
    )}
    onClick={onOpen}
  />
);

type DropDownMenuProps = {
  anchorEl: PopoverProps['anchorEl'];
  isOpen: boolean;
  onClose: (event: MouseEvent) => void;
  renderMenuItems: () => ReactElement<MenuItemProps, typeof MenuItem>[];
};

export const DropDownMenu = ({ anchorEl, isOpen, onClose, renderMenuItems }: DropDownMenuProps) => (
  <Menu
    anchorEl={anchorEl}
    open={isOpen}
    onClose={onClose}
    anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
    transformOrigin={{ vertical: 'top', horizontal: 'left' }}
  >
    {renderMenuItems()}
  </Menu>
);
