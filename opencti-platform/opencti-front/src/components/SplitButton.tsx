import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { Button, ButtonGroup, ClickAwayListener, Grow, MenuItem, MenuList, Paper, Popper } from '@mui/material';
import React, { FunctionComponent, useRef, useState } from 'react';
import { useFormatter } from './i18n';

interface SplitButtonProps {
  options: {
    option: string,
    icon?: JSX.Element,
    onClick?: React.MouseEventHandler<HTMLButtonElement>,
    disabled?: boolean,
  }[];
  defaultIndex?: number;
  style?: Record<string, unknown>;
}

const SplitButton: FunctionComponent<SplitButtonProps> = ({
  options,
  defaultIndex = 0,
  style,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(defaultIndex);
  const anchorRef = useRef<HTMLDivElement>(null);

  const handleMenuItemClick = (
    index: number,
  ) => {
    setSelectedIndex(index);
    setOpen(false);
  };

  const handleToggle = () => {
    setOpen((prevOpen) => !prevOpen);
  };

  const handleClose = (event: Event) => {
    if (
      anchorRef.current
      && anchorRef.current.contains(event.target as HTMLElement)
    ) {
      return;
    }

    setOpen(false);
  };

  return (
    <React.Fragment>
      <ButtonGroup variant="contained" ref={anchorRef} style={style}>
        <Button onClick={options[selectedIndex].onClick}>
          {options[selectedIndex].option} {options[selectedIndex].icon}
        </Button>
        <Button
          size="small"
          aria-controls={open ? 'split-button-menu' : undefined}
          aria-expanded={open ? 'true' : undefined}
          aria-label={t_i18n('select merge strategy')}
          aria-haspopup="menu"
          onClick={handleToggle}
        >
          {open
            ? <ArrowDropUp />
            : <ArrowDropDown />
          }
        </Button>
      </ButtonGroup>
      <Popper
        sx={{
          zIndex: 1,
        }}
        open={open}
        anchorEl={anchorRef.current}
        role={undefined}
        transition
        disablePortal
      >
        {({ TransitionProps, placement }) => (
          <Grow
            {...TransitionProps}
            style={{
              transformOrigin:
                placement === 'bottom' ? 'center top' : 'center bottom',
            }}
          >
            <Paper>
              <ClickAwayListener onClickAway={handleClose}>
                <MenuList id='split-button-menu' autoFocusItem>
                  {options.map(({ option, disabled }, index) => (
                    <MenuItem
                      key={option}
                      disabled={disabled}
                      selected={index === selectedIndex}
                      onClick={() => handleMenuItemClick(index)}
                    >
                      {option}
                    </MenuItem>
                  ))}
                </MenuList>
              </ClickAwayListener>
            </Paper>
          </Grow>
        )}
      </Popper>
    </React.Fragment>
  );
};

export default SplitButton;
