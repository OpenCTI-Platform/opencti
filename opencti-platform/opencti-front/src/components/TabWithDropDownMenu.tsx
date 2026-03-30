import { MouseEvent, ReactElement, useState } from 'react';
import { Box, MenuItemProps, PopoverProps, MenuItem } from '@mui/material';
import Tab, { TabProps } from '@mui/material/Tab';
import Menu from '@mui/material/Menu';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';

const TAB_STYLE = {
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
  // Compensate application of the 'inherit' variant instead
  // of the 'primary' variant to the tab. To be removed when possible.
  opacity: 1,
};

// Apply same CSS-driven case transform as applied to other tab labels
const LABEL_STYLE = {
  textTransform: 'lowercase',
  display: 'inline-block',
  '&::first-letter': {
    textTransform: 'uppercase',
  },
};

const ARROW_STYLE = {
  fontStyle: '20px',
};

type TabWithDropDownMenuProps = TabProps & {
  /** The Menu elements to show in the menu **/
  MenuItems: ReactElement<MenuItemProps, typeof MenuItem>[];
};

/**
 * A special type of Tab that displays a drop-down menu on click
 */
const TabWithDropDownMenu = (props: TabWithDropDownMenuProps) => {
  const [anchorPopover, setAnchorPopover] = useState<PopoverProps['anchorEl']>(null);

  const onOpenPopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(event.currentTarget);
  };

  const onClosePopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(null);
  };
  return (
    <>
      <Tab
        component="div"
        value={props.value}
        sx={TAB_STYLE}
        label={(
          <>
            <Box sx={LABEL_STYLE}>
              {props.label}
            </Box>
            {anchorPopover
              ? <ArrowDropUp sx={ARROW_STYLE} />
              : <ArrowDropDown sx={ARROW_STYLE} />}
          </>
        )}
        onClick={onOpenPopover}
      />
      <Menu
        anchorEl={anchorPopover}
        open={Boolean(anchorPopover)}
        onClose={onClosePopover}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {props.MenuItems}
      </Menu>
    </>
  );
};

export default TabWithDropDownMenu;
