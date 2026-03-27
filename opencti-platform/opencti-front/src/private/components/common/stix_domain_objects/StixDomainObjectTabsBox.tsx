import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { getCurrentTab } from '../../../../utils/utils';

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
  tabs: StixDomainObjectTabsBoxTab[];
  extraActions?: React.ReactNode;
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

const StixDomainObjectTabsBox = ({ basePath, extraActions, tabs }: StixDomainObjectTabsBoxProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  return (
    <Box
      sx={{
        borderBottom: 1,
        borderColor: 'divider',
        marginBottom: 3,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}
    >
      <Tabs value={getCurrentTab(location.pathname, basePath)}>
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
      </Tabs>
      {extraActions ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          {extraActions}
        </div>
      ) : null}
    </Box>
  );
};

export default StixDomainObjectTabsBox;
