import React, { FunctionComponent, useRef, useState } from 'react';
import { Button, ButtonGroup, ClickAwayListener, Grow, Paper, Popper, MenuItem, MenuList } from '@mui/material';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useFormatter } from './i18n';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';

interface CreateSplitControlledDialProps extends DrawerControlledDialProps {
  entityType: string;
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined';
  style?: React.CSSProperties;
  options?: string[];
  onOptionClick?: (option: string, index: number) => void;
}

const CreateSplitControlledDial: FunctionComponent<CreateSplitControlledDialProps> = ({
  onOpen,
  entityType,
  color = 'primary',
  size = 'medium',
  variant = 'contained',
  style,
  options = [],
  onOptionClick,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  const valueString = entityType ? t_i18n(`entity_${entityType}`) : t_i18n('Entity');
  const defaultButtonValue = t_i18n('', {
    id: 'Create ...',
    values: { entity_type: valueString },
  });

  const [open, setOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const anchorRef = useRef<HTMLDivElement | null>(null);

  const handleClickMain = () => {
    onOpen();
  };

  const handleToggle = () => {
    setOpen((prev) => !prev);
  };

  const handleMenuItemClick = (event: React.MouseEvent<HTMLLIElement>, index: number) => {
    setOpen(false);
    setSelectedIndex(index);

    if (onOptionClick && options[index]) {
      onOptionClick(options[index], index);
    }

    onOpen();
  };

  const handleClose = (event: MouseEvent | TouchEvent) => {
    if (anchorRef.current && anchorRef.current.contains(event.target as Node)) {
      return;
    }
    setOpen(false);
  };

  if (!canDisplayButton) return null;

  const mainButtonLabel
    = selectedIndex !== null && options[selectedIndex]
      ? options[selectedIndex]
      : defaultButtonValue;

  return (
    <>
      <ButtonGroup
        variant={variant}
        color={color}
        size={size}
        ref={anchorRef}
        sx={style ?? { marginLeft: theme.spacing(1) }}
        aria-label={mainButtonLabel}
      >
        <Button
          onClick={handleClickMain}
          title={mainButtonLabel}
          data-testid={`create-${entityType.toLowerCase()}-button`}
          disabled={mainButtonLabel === defaultButtonValue}
        >
          {mainButtonLabel}
        </Button>
        {options.length > 0 && (
          <Button
            size={size}
            aria-controls={open ? 'create-split-button-menu' : undefined}
            aria-expanded={open ? 'true' : undefined}
            aria-label={`${mainButtonLabel} (more options)`}
            aria-haspopup="menu"
            onClick={handleToggle}
          >
            <ArrowDropDownIcon />
          </Button>
        )}
      </ButtonGroup>
      {options.length > 0 && (
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
                  placement === 'bottom' ? 'center top' : 'center bottom',
              }}
            >
              <Paper>
                <ClickAwayListener onClickAway={handleClose}>
                  <MenuList id="create-split-button-menu" autoFocusItem>
                    {options.map((option, index) => (
                      <MenuItem
                        key={option}
                        selected={index === selectedIndex}
                        onClick={(event) => handleMenuItemClick(event, index)}
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
      )}
    </>
  );
};

export default CreateSplitControlledDial;
