import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Link, useLocation } from 'react-router-dom';
import React from 'react';
import { getCurrentTab } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';

type StixDomainObjectTabsBoxTab
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
  entity: { id: string; entity_type: string };
  basePath: string;
  tabs: StixDomainObjectTabsBoxTab[];
  extraActions?: React.ReactNode;
}

const StixDomainObjectTabsBox = ({ basePath, entity, extraActions, tabs }: StixDomainObjectTabsBoxProps) => {
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
      <Tabs
        value={getCurrentTab(location.pathname, entity.id, basePath)}
      >
        {tabs.includes('overview') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}`}
            value={`${basePath}/${entity.id}`}
            label={t_i18n('Overview')}
          />
        )}
        {tabs.includes('result') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/result`}
            value={`${basePath}/${entity.id}/result`}
            label={t_i18n('Result')}
          />
        )}
        {tabs.includes('knowledge') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/knowledge`}
            value={`${basePath}/${entity.id}/knowledge`}
            label={t_i18n('Knowledge')}
          />
        )}
        {tabs.includes('content') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/content`}
            value={`${basePath}/${entity.id}/content`}
            label={t_i18n('Content')}
          />
        )}
        {tabs.includes('analyses') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/analyses`}
            value={`${basePath}/${entity.id}/analyses`}
            label={t_i18n('Analyses')}
          />
        )}
        {tabs.includes('sightings') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/sightings`}
            value={`${basePath}/${entity.id}/sightings`}
            label={t_i18n('Sightings')}
          />
        )}
        {tabs.includes('entities') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/entities`}
            value={`${basePath}/${entity.id}/entities`}
            label={t_i18n('Entities')}
          />
        )}
        {tabs.includes('observables') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/observables`}
            value={`${basePath}/${entity.id}/observables`}
            label={t_i18n('Observables')}
          />
        )}
        {tabs.includes('files') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/files`}
            value={`${basePath}/${entity.id}/files`}
            label={t_i18n('Data')}
          />
        )}
        {tabs.includes('history') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/history`}
            value={`${basePath}/${entity.id}/history`}
            label={t_i18n('History')}
          />
        )}
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
