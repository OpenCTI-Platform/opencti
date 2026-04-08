import { Link } from 'react-router-dom';
import MenuItem from '@mui/material/MenuItem';
import { DropDownMenu, useDropDownMenuState } from '../../../components/TabWithDropDownMenu';
import { useCustomViews } from './useCustomViews';
import { type CustomViewDisplayMode } from './useCustomViewTabs';

interface CustomViewTabDropDownMenuProps {
  displayMode: CustomViewDisplayMode;
  customViews: ReturnType<typeof useCustomViews>['customViews'];
  dropDownMenuState: ReturnType<typeof useDropDownMenuState>;
  currentCustomViewTab?: string;
}

const CustomViewTabDropDownMenu = ({ displayMode, customViews, dropDownMenuState, currentCustomViewTab }: CustomViewTabDropDownMenuProps) => {
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
        const isSelected = currentCustomViewTab === path;
        return (
          <MenuItem
            key={id}
            role="link"
            component={Link}
            to={path}
            selected={isSelected}
          >
            {name}
          </MenuItem>
        );
      })}
    />
  );
};

export default CustomViewTabDropDownMenu;
