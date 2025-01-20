// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, useEffect } from 'react';
import { Route, Routes, useParams, Link, useLocation, Navigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import DraftEntities from '@components/drafts/DraftEntities';
import { DraftContextBannerMutation } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import DraftRelationships from '@components/drafts/DraftRelationships';
import DraftSightings from '@components/drafts/DraftSightings';
import { DraftRootQuery } from '@components/drafts/__generated__/DraftRootQuery.graphql';
import { usePreloadedQuery } from 'react-relay';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { getCurrentTab } from '../../../utils/utils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';

const draftRootQuery = graphql`
  query DraftRootQuery($id: String!) {
    draftWorkspace(id: $id) {
      id
      name
      created_at
      objectsCount {
        containersCount
        entitiesCount
        observablesCount
        relationshipsCount
        sightingsCount
        totalCount
      }
    }
  }
`;

const RootDraftComponent = ({ draftId, queryRef }) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();

  const { draftWorkspace } = usePreloadedQuery<DraftRootQuery>(draftRootQuery, queryRef);
  if (!draftWorkspace) {
    return (<ErrorNotFound />);
  }

  // switch to draft
  const [commitSwitchToDraft] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation);

  useEffect(() => {
    if (!draftContext || draftContext.id !== draftId) {
      commitSwitchToDraft({
        variables: {
          input: [{ key: 'draft_context', value: [draftId] }],
        },
        onCompleted: () => {
          MESSAGING$.notifySuccess(<span>{t_i18n('You are now in Draft Mode')}</span>);
        },
        onError: (error) => {
          const { errors } = (error as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        },
      });
    }
  }, [commitSwitchToDraft]);

  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('Drafts'), link: '/dashboard/drafts' },
        { label: draftWorkspace.name, current: true },
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
          id="tabs-container"
          value={getCurrentTab(location.pathname, draftId, '/dashboard/drafts/entities')}
        >
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/entities`}
            value={`/dashboard/drafts/${draftId}/entities`}
            label={
              <span>{t_i18n('Entities')} ({draftWorkspace.objectsCount.entitiesCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/observables`}
            value={`/dashboard/drafts/${draftId}/observables`}
            label={
              <span>{t_i18n('Observables')} ({draftWorkspace.objectsCount.observablesCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/relationships`}
            value={`/dashboard/drafts/${draftId}/relationships`}
            label={
              <span>{t_i18n('Relationships')} ({draftWorkspace.objectsCount.relationshipsCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/sightings`}
            value={`/dashboard/drafts/${draftId}/sightings`}
            label={
              <span>{t_i18n('Sightings')} ({draftWorkspace.objectsCount.sightingsCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/containers`}
            value={`/dashboard/drafts/${draftId}/containers`}
            label={
              <span>{t_i18n('Containers')} ({draftWorkspace.objectsCount.containersCount})</span>
            }
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
          element={<DraftRelationships/>}
        />
        <Route
          path="/sightings"
          element={<DraftSightings/>}
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
  const queryRef = useQueryLoading<DraftRootQuery>(draftRootQuery, { id: draftId });
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootDraftComponent draftId={draftId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default RootDraft;
