import React, { FunctionComponent, useRef, useState } from 'react';
import Button, { ButtonVariant } from '@common/button/Button';
import { ClickAwayListener, Grow, Paper, Popper, MenuItem, MenuList } from '@mui/material';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useFormatter } from './i18n';
import { ButtonColorKey, type ButtonSize } from '@common/button/Button.types';

interface CreateSplitControlledDialProps extends DrawerControlledDialProps {
  entityType: string;
  color?: ButtonColorKey;
  size?: ButtonSize;
  variant?: ButtonVariant;
  style?: React.CSSProperties;
  options?: string[];
  onOptionClick?: (option: string, index: number) => void;
}

const CreateSplitControlledDial: FunctionComponent<CreateSplitControlledDialProps> = ({
  onOpen,
  entityType,
  color,
  size = 'default',
  variant = 'primary',
  style,
  options = [],
  onOptionClick,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const valueString = entityType
    ? t_i18n(`entity_${entityType}`)
    : t_i18n('Entity');
  const defaultButtonValue = t_i18n('', {
    id: 'Create ...',
    values: { entity_type: valueString },
  });

  const [open, setOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(options.length > 0 ? 0 : null);

  const anchorRef = useRef<HTMLButtonElement | null>(null);

  const handleToggle = () => {
    setOpen((prev) => !prev);
  };

  const handleMenuItemClick = (
    event: React.MouseEvent<HTMLLIElement>,
    index: number,
  ) => {
    setOpen(false);
    setSelectedIndex(index);

    if (onOptionClick && options[index]) {
      onOptionClick(options[index], index);
    }
    onOpen();
  };

  const handleClose = (event: MouseEvent | TouchEvent) => {
    if (
      anchorRef.current
      && event.target instanceof Node
      && anchorRef.current.contains(event.target)
    ) {
      return;
    }
    setOpen(false);
  };

  const handleMainClickNoOptions = () => {
    onOpen();
  };

  const hasOptions = options.length > 0;

  return (
    <>
      <Button
        variant={variant}
        color={color}
        size={size}
        ref={anchorRef}
        sx={style ?? { marginLeft: theme.spacing(1) }}
        onClick={hasOptions ? handleToggle : handleMainClickNoOptions}
        title={defaultButtonValue}
        endIcon={hasOptions ? <ArrowDropDownIcon /> : undefined}
        data-testid={`create-${entityType.toLowerCase()}-button`}
      >
        {defaultButtonValue}
      </Button>

      {hasOptions && (
        <Popper
          sx={{ zIndex: 1200 }}
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
                  placement === 'bottom'
                    ? 'center top'
                    : 'center bottom',
              }}
            >
              <Paper>
                <ClickAwayListener onClickAway={handleClose}>
                  <MenuList
                    id="create-split-button-menu"
                    autoFocusItem
                  >
                    {options.map((option, index) => (
                      <MenuItem
                        key={option}
                        selected={index === selectedIndex}
                        onClick={(event) =>
                          handleMenuItemClick(event, index)
                        }
                      >
                        {t_i18n(option)}
                      </MenuItem>
                    ))}
                  </MenuList>
                </ClickAwayListener>
              </Paper>
            </Grow>
          )}
        </Popper>
      )}
    </>
  );
};

export default CreateSplitControlledDial;
