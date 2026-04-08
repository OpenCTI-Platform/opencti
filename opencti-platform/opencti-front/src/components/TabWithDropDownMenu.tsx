import { MouseEvent, ReactElement, useState } from 'react';
import { Box, MenuItemProps, PopoverProps, MenuItem, SxProps } from '@mui/material';
import Tab, { TabProps } from '@mui/material/Tab';
import Menu from '@mui/material/Menu';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';

const arrowStyle: SxProps = {
  fontSize: '20px',
};

type TabWithDropDownMenuProps = TabProps & {
  /** The Menu elements to show in the menu **/
  renderMenuItems: () => ReactElement<MenuItemProps, typeof MenuItem>[];
  /** Should skip creating Tab and Menu components **/
  skip?: boolean;
};

/**
 * A special type of Tab that displays a drop-down menu on click.
 * Unorthodoxly this functionality is exposed as a hook as we want to provide
 * two distinct components given the <Menu> component cannot
 */
const useTabWithDropDownMenu = ({ skip, renderMenuItems, label, ...tabProps }: TabWithDropDownMenuProps) => {
  const [anchorPopover, setAnchorPopover] = useState<PopoverProps['anchorEl']>(null);

  const onOpenPopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(event.currentTarget);
  };

  const onClosePopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(null);
  };
  return {
    TabWithDropDown: (skip
      ? null
      : (
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
              // Compensate application of the 'inherit' variant instead
              // of the 'primary' variant to the tab. To be removed when possible.
              opacity: 1,
              // Use default text color
              color: 'text.secondary',
            }}
            label={(
              <>
                <Box sx={{
                  textTransform: 'lowercase',
                  display: 'inline-block',
                  '&::first-letter': {
                    textTransform: 'uppercase',
                  },
                }}
                >
                  {label}
                </Box>
                {anchorPopover
                  ? <ArrowDropUp sx={arrowStyle} />
                  : <ArrowDropDown sx={arrowStyle} />}
              </>
            )}
            onClick={onOpenPopover}
          />
        )
    ),
    DropDown: (skip
      ? null
      : (
          <Menu
            anchorEl={anchorPopover}
            open={Boolean(anchorPopover)}
            onClose={onClosePopover}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
            transformOrigin={{ vertical: 'top', horizontal: 'left' }}
          >
            {renderMenuItems()}
          </Menu>
        )
    ),
  };
};

export default useTabWithDropDownMenu;
