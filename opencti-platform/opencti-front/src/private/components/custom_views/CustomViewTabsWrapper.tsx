import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { MenuItem } from '@mui/material';
import Tab from '@mui/material/Tab';
import { getCurrentTab } from '../../../utils/utils';
import { useFormatter } from '../../../components/i18n';
import useTabWithDropDownMenu from '../../../components/TabWithDropDownMenu';
import { CUSTOM_VIEW_TAB_VALUE, useCustomViews } from './useCustomViews';

const MENU_ITEM_LINK_STYLE = {
  padding: '10px',
  color: 'inherit',
};

interface CustomViewTabsWrapperProps {
  /** Entity type being visited **/
  entityType: string;
  /** Original base path where the <Tabs> are displayed **/
  basePath: string;
  /**
   * Render prop: provides the <Tab> and potential <Menu> components
   * to place within calling component's hierarchy.
   * Avoid placing the <Menu> component under the <Tabs> parent
   */
  render: (parms: {
    CustomViewsTab: ReactNode;
    CustomViewsDropDown: ReactNode;
    currentCustomViewTab?: string;
  }) => ReactNode;
}

const CustomViewTabsWrapper = ({ basePath, entityType, render }: CustomViewTabsWrapperProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { customViews, getCurrentCustomViewTab } = useCustomViews(entityType);
  const currentCustomViewTab = getCurrentCustomViewTab(location.pathname, basePath);

  const shouldDisplayCustomViewTab = customViews.length === 1;
  const shouldDisplayCustomViewTabWithDropDown = customViews.length > 1;
  const { TabWithDropDown: CustomViewTabWithDropDown, DropDown: CustomViewsDropDown } = useTabWithDropDownMenu({
    skip: !shouldDisplayCustomViewTabWithDropDown,
    value: CUSTOM_VIEW_TAB_VALUE,
    label: t_i18n('Custom view'),
    renderMenuItems: () => customViews.map(({ id, name, path }) => {
      const isSelected = getCurrentTab(location.pathname, basePath) === path;
      return (
        <MenuItem key={id} sx={{ p: 0, color: isSelected ? 'primary.main' : undefined }}>
          <Link role="link" style={MENU_ITEM_LINK_STYLE} to={`${basePath}/${path}`}>{name}</Link>
        </MenuItem>
      );
    }),
  });
  const CustomViewsTab = shouldDisplayCustomViewTab ? (
    <Tab
      component={Link}
      to={customViews[0].path}
      value={CUSTOM_VIEW_TAB_VALUE}
      label={customViews[0].name}
    />
  ) : shouldDisplayCustomViewTabWithDropDown
    ? CustomViewTabWithDropDown : null;
  return render({
    CustomViewsTab,
    CustomViewsDropDown,
    currentCustomViewTab,
  });
};

export default CustomViewTabsWrapper;
