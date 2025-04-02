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
import { graphql, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { interval } from 'rxjs';
import ConnectorWorkLine from '@components/data/connectors/ConnectorWorkLine';
import Paper from '@mui/material/Paper';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { getCurrentTab } from '../../../utils/utils';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import Import from '../data/import/Import';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { TEN_SECONDS } from '../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const draftRootQuery = graphql`
  query DraftRootQuery($id: String!) {
    draftWorkspace(id: $id) {
      ...DraftRootFragment
    }
  }
`;

const draftRootFragment = graphql`
  fragment DraftRootFragment on DraftWorkspace {
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
    draft_status
    validationWork {
      name
      received_time
      processed_time
      completed_time
      status
      tracking {
        import_expected_number
        import_processed_number
      }
      errors {
        timestamp
        message
        sequence
        source
      }
    }
  }
`;

const RootDraftComponent = ({ draftId, queryRef, refetch }) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();

  const { draftWorkspace } = usePreloadedQuery<DraftRootQuery>(draftRootQuery, queryRef);
  if (!draftWorkspace) {
    return (<ErrorNotFound />);
  }

  const { name, objectsCount, draft_status, validationWork } = useFragment(draftRootFragment, draftWorkspace);
  const isDraftReadOnly = draft_status !== 'open';

  // switch to draft
  const [commitSwitchToDraft] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation);

  useEffect(() => {
    if (!isDraftReadOnly && (!draftContext || draftContext.id !== draftId)) {
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

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  // If me user is not yet updated to be in draft, display loader
  if (!isDraftReadOnly && !draftContext) {
    return (<Loader/>);
  }

  return (
    <>
      {isDraftReadOnly && (
      <>
        <Breadcrumbs elements={[
          { label: t_i18n('Drafts'), link: '/dashboard/drafts' },
          { label: name, current: true },
        ]}
        />
        {validationWork && (
        <Paper
          key={validationWork.id}
          style={{ margin: '10px 0 20px 0', padding: '15px', borderRadius: 4, position: 'relative' }}
          variant="outlined"
        >
          <ConnectorWorkLine
            workId={validationWork.id}
            workName={validationWork.name}
            workStatus={validationWork.status}
            workReceivedTime={validationWork.received_time}
            workEndTime={validationWork.completed_time}
            workExpectedNumber={validationWork.tracking?.import_processed_number}
            workProcessedNumber={validationWork.tracking?.import_expected_number}
            workErrors={validationWork.errors}
            readOnly
          />
        </Paper>
        )}
      </>
      )}
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
              <span>{t_i18n('Entities')} ({objectsCount.entitiesCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/observables`}
            value={`/dashboard/drafts/${draftId}/observables`}
            label={
              <span>{t_i18n('Observables')} ({objectsCount.observablesCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/relationships`}
            value={`/dashboard/drafts/${draftId}/relationships`}
            label={
              <span>{t_i18n('Relationships')} ({objectsCount.relationshipsCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/sightings`}
            value={`/dashboard/drafts/${draftId}/sightings`}
            label={
              <span>{t_i18n('Sightings')} ({objectsCount.sightingsCount})</span>
            }
          />
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/containers`}
            value={`/dashboard/drafts/${draftId}/containers`}
            label={
              <span>{t_i18n('Containers')} ({objectsCount.containersCount})</span>
            }
          />
          {!isDraftReadOnly && (
          <Tab
            component={Link}
            to={`/dashboard/drafts/${draftId}/files`}
            value={`/dashboard/drafts/${draftId}/files`}
            label={t_i18n('Files')}
          />)}
        </Tabs>
      </Box>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/drafts/${draftId}/entities`} replace={true} />}
        />
        <Route
          path="/entities"
          element={<DraftEntities entitiesType={'Stix-Domain-Object'} excludedEntitiesType={'Container'} isReadOnly={isDraftReadOnly}/>}
        />
        <Route
          path="/observables"
          element={<DraftEntities entitiesType={'Stix-Cyber-Observable'} isReadOnly={isDraftReadOnly}/>}
        />
        <Route
          path="/relationships"
          element={<DraftRelationships isReadOnly={isDraftReadOnly}/>}
        />
        <Route
          path="/sightings"
          element={<DraftSightings isReadOnly={isDraftReadOnly}/>}
        />
        <Route
          path="/containers"
          element={<DraftEntities entitiesType={'Container'} isReadOnly={isDraftReadOnly}/>}
        />
        <Route
          path="/files"
          element={<Import inDraftOverview/>}
        />
      </Routes>
    </>
  );
};

const RootDraft = () => {
  const { draftId } = useParams() as { draftId: string };
  const [queryRef, loadQuery] = useQueryLoader<DraftRootQuery>(draftRootQuery);
  useEffect(() => {
    loadQuery({ id: draftId }, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({ id: draftId }, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootDraftComponent draftId={draftId} queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default RootDraft;
