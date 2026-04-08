import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Stack from '@mui/material/Stack';
import { getCurrentTab } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import useCustomViewTabs from '@components/custom_views/useCustomViewTabs';
import CustomViewTab from '@components/custom_views/CustomViewTab';
import CustomViewTabDropDownMenu from '@components/custom_views/CustomViewTabDropDownMenu';

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

interface CustomViewTabsProps {
  basePath: string;
  entityType: string;
  staticTabs: ReactNode;
  currentTab: string;
}

const CustomViewTabs = ({ basePath, entityType, staticTabs, currentTab }: CustomViewTabsProps) => {
  const {
    customViews,
    displayMode,
    dropDownMenuState,
    currentCustomViewTab,
  } = useCustomViewTabs({ basePath, entityType });

  return (
    <>
      <Tabs value={currentCustomViewTab ?? currentTab}>
        {staticTabs}
        <CustomViewTab
          displayMode={displayMode}
          customViews={customViews}
          dropDownMenuState={dropDownMenuState}
        />
      </Tabs>
      <CustomViewTabDropDownMenu
        currentCustomViewTab={currentCustomViewTab}
        customViews={customViews}
        displayMode={displayMode}
        dropDownMenuState={dropDownMenuState}
      />
    </>
  );
};

/**
 * Tabs container shared across all SDO pages.
 * Applies common logic to display (or not) the "Custom views" tab.
 */
const StixDomainObjectTabsBox = (props: StixDomainObjectTabsBoxProps) => {
  const { basePath, entityType, extraActions, tabs } = props;
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isCustomViewFeatureEnabled = isFeatureEnable('CUSTOM_VIEW');
  const currentTab = getCurrentTab(location.pathname, basePath);

  const staticTabs = TABS_INFO.map(({ tab, path, label }) =>
    tabs.includes(tab) && (
      <Tab
        key={tab}
        component={Link}
        to={path}
        value={path}
        label={t_i18n(label)}
      />
    ));

  return (
    <Box sx={{
      borderBottom: 1,
      borderColor: 'divider',
      marginBottom: 3,
    }}
    >
      {isCustomViewFeatureEnabled ? (
        <CustomViewTabs
          basePath={basePath}
          entityType={entityType}
          staticTabs={staticTabs}
          currentTab={currentTab}
        />
      ) : (
        <Tabs value={currentTab}>
          {staticTabs}
        </Tabs>
      )}
      {extraActions ? (
        <Stack gap={2} direction="row" justifyContent="space-between" alignItems="center">
          {extraActions}
        </Stack>
      ) : null}
    </Box>
  );
};

export default StixDomainObjectTabsBox;
