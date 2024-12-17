// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useParams, Link, useLocation, Navigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import DraftEntities from '@components/drafts/DraftEntities';
import { getCurrentTab } from '../../../utils/utils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';

const RootDraftComponent = ({ draftId }) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('Drafts'), link: '/dashboard/drafts' },
        { label: draftId, current: true },
      ]}
      />
      <Box
        sx={{
          borderBottom: 1,
          borderColor: 'divider',
          marginBottom: 3,
        }}
      >
        <Tabs
          value={getCurrentTab(location.pathname, draftId, '/dashboard/drafts')}
        >
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/entities`}
            value={`/dashboard/drafts/${draftId}/entities`}
            label={t_i18n('Entities')}
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/observables`}
            value={`/dashboard/drafts/${draftId}/observables`}
            label={t_i18n('Observables')}
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/relationships`}
            value={`/dashboard/drafts/${draftId}/relationships`}
            label={t_i18n('Relationships')}
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/sightings`}
            value={`/dashboard/drafts/${draftId}/sightings`}
            label={t_i18n('Sightings')}
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/containers`}
            value={`/dashboard/drafts/${draftId}/containers`}
            label={t_i18n('Containers')}
          />
        </Tabs>
      </Box>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/drafts/${draftId}/entities`} replace={true} />}
        />
        <Route
          path="/entities"
          element={<DraftEntities entitiesType={'Stix-Domain-Object'}/>}
        />
        <Route
          path="/observables"
          element={<DraftEntities entitiesType={'Stix-Cyber-Observable'}/>}
        />
        <Route
          path="/relationships"
          element={<DraftEntities/>}
        />
        <Route
          path="/sightings"
          element={<DraftEntities/>}
        />
        <Route
          path="/containers"
          element={<DraftEntities entitiesType={'Container'}/>}
        />
      </Routes>
    </>
  );
};

const RootDraft = () => {
  const { draftId } = useParams() as { draftId: string };
  return (
    <RootDraftComponent draftId={draftId} />
  );
};

export default RootDraft;
