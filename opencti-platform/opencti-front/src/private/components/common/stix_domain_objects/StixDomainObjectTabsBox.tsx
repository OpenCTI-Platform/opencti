import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { MenuItem } from '@mui/material';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { getCurrentTab } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';
import TabWithDropDownMenu from '../../../../components/TabWithDropDownMenu';
import { CUSTOM_VIEW_TAB_VALUE, useCustomViews } from '../../custom_views/useCustomViews';

export type StixDomainObjectTabsBoxTab
  = | 'overview'
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
const TABS_INFO = Object.freeze([{
  tab: 'overview',
  path: '',
  label: 'Overview',
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
}] satisfies TabInfo[]);

const CONTAINER_STYLE = {
  borderBottom: 1,
  borderColor: 'divider',
  marginBottom: 3,
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
};

const EXTRA_ACTIONS_STYLE = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: '10px',
};

const MENU_ITEM_STYLE = {
  // Maximize link area
  padding: 0,
};

const MENU_ITEM_LINK_STYLE = {
  padding: '10px',
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
        {customViews.length === 1 ? (
          <Tab
            component={Link}
            to={customViews[0].path}
            value={CUSTOM_VIEW_TAB_VALUE}
            label={customViews[0].name}
          />
        ) : customViews.length > 1 ? (
          <TabWithDropDownMenu
            value={CUSTOM_VIEW_TAB_VALUE}
            label={t_i18n('Custom views')}
            MenuItems={
              customViews.map(({ id, name, path }) => (
                <MenuItem key={id} style={MENU_ITEM_STYLE}>
                  <Link role="link" style={MENU_ITEM_LINK_STYLE} to={`${basePath}/${path}`}>{name}</Link>
                </MenuItem>
              ))
            }
          />
        ) : null
        }
      </Tabs>
      {extraActions ? (
        <div style={EXTRA_ACTIONS_STYLE}>
          {extraActions}
        </div>
      ) : null}
    </Box>
  );
};

export default StixDomainObjectTabsBox;
