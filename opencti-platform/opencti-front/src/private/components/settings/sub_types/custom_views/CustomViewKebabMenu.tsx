import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import ToggleButton from '@mui/material/ToggleButton';
import { useFormatter } from '../../../../../components/i18n';
import CustomViewDuplicationDialog from './CustomViewDuplicationDialog';
import type { CustomViewKebabMenu_customView$key } from './__generated__/CustomViewKebabMenu_customView.graphql';

const kebabMenuFragment = graphql`
  fragment CustomViewKebabMenu_customView on CustomView {
    id
    name
    target_entity_type
    ...CustomViewDuplicationDialog_Fragment
  }
`;

interface CustomViewKebabMenuProps {
  data: CustomViewKebabMenu_customView$key;
}

const noop = () => {};

const useDuplicate = (onDuplicate = noop) => {
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);
  const [duplicating, setDuplicating] = useState(false);
  const handleDuplication = () => {
    onDuplicate();
    setDisplayDuplicate(true);
  };

  return {
    displayDuplicate,
    setDisplayDuplicate,
    handleCloseDuplicate,
    duplicating,
    setDuplicating,
    handleDuplication,
  };
};

const CustomViewKebabMenu = ({ data }: CustomViewKebabMenuProps) => {
  const customView = useFragment(kebabMenuFragment, data);
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement, MouseEvent>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const {
    displayDuplicate,
    duplicating,
    setDuplicating,
    handleDuplication,
    handleCloseDuplicate,
  } = useDuplicate(handleClose);
  return (
    <div>
      <ToggleButton
        aria-label={t_i18n('Popover of custom view actions')}
        value="popover"
        size="small"
        color="primary"
        id="custom-view-kebab-button"
        aria-controls={open ? 'custom-view-kebab-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
        sx={{ height: '100%' }}
      >
        <MoreVert color="primary" fontSize="small" />
      </ToggleButton>
      <Menu
        id="custom-view-kebab-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        slotProps={{
          list: {
            'aria-labelledby': 'workspace-kebab-button',
          },
        }}
      >
        <MenuItem onClick={handleDuplication}>{t_i18n('Duplicate the custom view')}</MenuItem>
      </Menu>
      <CustomViewDuplicationDialog
        data={customView}
        displayDuplicate={displayDuplicate}
        handleCloseDuplicate={handleCloseDuplicate}
        duplicating={duplicating}
        setDuplicating={setDuplicating}
      />
    </div>
  );
};

export default CustomViewKebabMenu;
