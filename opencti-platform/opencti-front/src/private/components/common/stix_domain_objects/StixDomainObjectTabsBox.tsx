import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { MenuItem } from '@mui/material';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Stack from '@mui/material/Stack';
import { getCurrentTab } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';
import { CUSTOM_VIEW_TAB_VALUE, useCustomViews } from '../../custom_views/useCustomViews';
import useTabWithDropDownMenu from '../../../../components/TabWithDropDownMenu';

export type StixDomainObjectTabsBoxTab
  = | 'overview'
    | 'result'
    | 'knowledge'
    | 'content'
    | 'analyses'
    | 'sightings'
    | 'entities'
    | 'observables'
    | 'files'
    | 'history';

interface StixDomainObjectTabsBoxProps {
  basePath: string;
  entityType: string;
  tabs: StixDomainObjectTabsBoxTab[];
  extraActions?: ReactNode;
}

interface TabInfo {
  /** Tab identifier **/
  tab: StixDomainObjectTabsBoxTab;
  /** Relative path to navigate to **/
  path: string;
  /** Label key **/
  label: string;
}

// Information about static tabs.
// Order is important, will be reflected in the UI.
const TABS_INFO: readonly TabInfo[] = [{
  tab: 'overview',
  path: '',
  label: 'Overview',
}, {
  tab: 'result',
  path: 'result',
  label: 'Result',
}, {
  tab: 'knowledge',
  path: 'knowledge',
  label: 'Knowledge',
}, {
  tab: 'content',
  path: 'content',
  label: 'Content',
}, {
  tab: 'analyses',
  path: 'analyses',
  label: 'Analyses',
}, {
  tab: 'sightings',
  path: 'sightings',
  label: 'Sightings',
}, {
  tab: 'entities',
  path: 'entities',
  label: 'Entities',
}, {
  tab: 'observables',
  path: 'observables',
  label: 'Observables',
}, {
  tab: 'files',
  path: 'files',
  label: 'Data',
}, {
  tab: 'history',
  path: 'history',
  label: 'History',
}];

const CONTAINER_STYLE = {
  borderBottom: 1,
  borderColor: 'divider',
  marginBottom: 3,
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
};

const MENU_ITEM_LINK_STYLE = {
  padding: '10px',
  color: 'inherit',
};

/**
 * Tabs container shared across all SDO pages.
 * Applies common logic to display (or not) the "Custom views" tab.
 */
const StixDomainObjectTabsBox = (props: StixDomainObjectTabsBoxProps) => {
  const { basePath, entityType, extraActions, tabs } = props;
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { customViews, getCurrentCustomViewTab } = useCustomViews(entityType);
  const currentTab = getCurrentCustomViewTab(location.pathname, basePath)
    ?? getCurrentTab(location.pathname, basePath);

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
  return (
    <Box sx={CONTAINER_STYLE}>
      <Tabs value={currentTab}>
        {
          TABS_INFO.map(({ tab, path, label }) =>
            tabs.includes(tab) && (
              <Tab
                key={tab}
                component={Link}
                to={path}
                value={path}
                label={t_i18n(label)}
              />
            ))
        }
        {shouldDisplayCustomViewTab ? (
          <Tab
            component={Link}
            to={customViews[0].path}
            value={CUSTOM_VIEW_TAB_VALUE}
            label={customViews[0].name}
          />
        ) : null}
        {shouldDisplayCustomViewTabWithDropDown ? CustomViewTabWithDropDown : null }
      </Tabs>
      {shouldDisplayCustomViewTabWithDropDown ? CustomViewsDropDown : null }
      {extraActions ? (
        <Stack gap={2} direction="row" justifyContent="space-between" alignItems="center">
          {extraActions}
        </Stack>
      ) : null}
    </Box>
  );
};

export default StixDomainObjectTabsBox;
