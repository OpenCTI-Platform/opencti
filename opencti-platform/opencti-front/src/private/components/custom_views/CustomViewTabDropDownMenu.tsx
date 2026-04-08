import { Link } from 'react-router-dom';
import MenuItem from '@mui/material/MenuItem';
import { DropDownMenu, useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { useCustomViews } from './useCustomViews';
import { type CustomViewDisplayMode } from './useCustomViewTabs';

interface CustomViewTabDropDownMenuProps {
  displayMode: CustomViewDisplayMode;
  customViews: ReturnType<typeof useCustomViews>['customViews'];
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  currentCustomViewMenuItem?: string;
}

const CustomViewTabDropDownMenu = ({ displayMode, customViews, dropDownMenuState, currentCustomViewMenuItem }: CustomViewTabDropDownMenuProps) => {
  const { anchorEl, isOpen, onClose } = dropDownMenuState;
  if (displayMode !== 'dropdown') {
    return null;
  }
  return (
    <DropDownMenu
      anchorEl={anchorEl}
      isOpen={isOpen}
      onClose={onClose}
      renderMenuItems={() => customViews.map(({ id, name, path }) => {
        const isSelected = currentCustomViewMenuItem === path;
        return (
          <MenuItem
            key={id}
            selected={isSelected}
            role="link"
            component={Link}
            to={path}
            sx={{
              '&.Mui-selected': {
                boxShadow: 'none',
                background: 'none',
                color: 'primary.main',
              },
              '&.Mui-selected:hover': {
                boxShadow: 'none',
                background: 'none',
                color: 'primary.main',
              },
            }}
          >
            {name}
          </MenuItem>
        );
      })}
    />
  );
};

export default CustomViewTabDropDownMenu;
