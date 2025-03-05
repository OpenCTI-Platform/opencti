// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, useEffect } from 'react';
import { Route, Routes, useParams, Link, useLocation, Navigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import { useTheme } from '@mui/styles';
import Tab from '@mui/material/Tab';
import DraftEntities from '@components/drafts/DraftEntities';
import { DraftContextBannerMutation } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import DraftRelationships from '@components/drafts/DraftRelationships';
import DraftSightings from '@components/drafts/DraftSightings';
import { DraftRootQuery } from '@components/drafts/__generated__/DraftRootQuery.graphql';
import { graphql, useFragment, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { getCurrentTab } from '../../../utils/utils';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import Import from '../data/import/Import';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { truncate } from '../../../utils/String';
import { hexToRGB } from '../../../utils/Colors';

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
      received_time
      processed_time
      completed_time
      status
      tracking {
        import_expected_number
        import_processed_number
      }
    }
  }
`;

const RootDraftComponent = ({ draftId, queryRef }) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const draftContext = useDraftContext();

  const { draftWorkspace } = usePreloadedQuery<DraftRootQuery>(draftRootQuery, queryRef);
  if (!draftWorkspace) {
    return (<ErrorNotFound />);
  }

  const { name, objectsCount, draft_status, validationWork } = useFragment(draftRootFragment, draftWorkspace);
  const isDraftReadOnly = draft_status !== 'open';
  const currentProgress = validationWork?.tracking?.import_processed_number ?? '0';
  const requiredProgress = validationWork?.tracking?.import_expected_number ?? '0';
  const isValidating = validationWork?.status === 'wait' || validationWork?.status === 'progress';
  const validationLabel = isValidating ? `${t_i18n('Ingesting')}: ${currentProgress}/${requiredProgress}` : t_i18n('Completed');
  const validationColor = isValidating ? draftColor : theme.palette.success.main;

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

  return (
    <>
      {isDraftReadOnly && (
      <>
        <Breadcrumbs elements={[
          { label: t_i18n('Drafts'), link: '/dashboard/drafts' },
          { label: name, current: true },
        ]}
        />
        <div style={{ display: 'flex', gap: 10 }}>
          <Tooltip title={name}>
            <Typography
              variant="h1"
              sx={{
                margin: 0,
                lineHeight: 'unset',
              }}
            >
              {truncate(name, 80)}
            </Typography>
          </Tooltip>
          <Chip
            variant="outlined"
            label={validationLabel}
            style={{
              marginBottom: 10,
              color: validationColor,
              borderColor: validationColor,
              backgroundColor: hexToRGB(validationColor),
            }}
          />
        </div>
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
