import React, { UIEvent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import CustomViewDuplicationDialog from './CustomViewDuplicationDialog';
import type { CustomViewMenu_customView$key } from './__generated__/CustomViewMenu_customView.graphql';
import CustomViewDeletionDialog from './CustomViewDeletionDialog';

const menuFragment = graphql`
  fragment CustomViewMenu_customView on CustomView {
    id
    name
    targetEntityType
    ...CustomViewDuplicationDialog_Fragment
  }
`;

interface CustomViewMenuProps {
  data: CustomViewMenu_customView$key;
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

const CustomViewMenu = ({ data }: CustomViewMenuProps) => {
  const customView = useFragment(menuFragment, data);
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const navigate = useNavigate();
  const handleClick = (event: React.MouseEvent<HTMLElement, MouseEvent>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleDeleted = () => {
    navigate(`/dashboard/settings/customization/entity_types/${customView.targetEntityType}/custom-views`);
  };

  const {
    displayDuplicate,
    duplicating,
    setDuplicating,
    handleDuplication,
    handleCloseDuplicate,
  } = useDuplicate(handleClose);
  const deletion = useDeletion({ handleClose });
  const handleOpenDelete = (e: UIEvent) => {
    setAnchorEl(null);
    deletion.handleOpenDelete(e);
  };
  return (
    <div>
      <IconButton
        aria-label={t_i18n('Popover of custom view actions')}
        value="popover"
        color="secondary"
        id="custom-view-menu-button"
        aria-controls={open ? 'custom-view-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
        variant="secondary"
        size="default"
      >
        <MoreVert color="primary" fontSize="small" />
      </IconButton>
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
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <CustomViewDeletionDialog
        id={customView.id}
        deletion={deletion}
        onDeleted={handleDeleted}
      />
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

export default CustomViewMenu;
