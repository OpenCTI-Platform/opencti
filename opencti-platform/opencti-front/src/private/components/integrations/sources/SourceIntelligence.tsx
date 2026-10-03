import React, { Suspense, useState } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { DashboardOutlined, RefreshOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import EEChip from '@components/common/entreprise_edition/EEChip';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { EXPLORE_EXUPDATE, INGESTION_SETINGESTIONS, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../../components/Theme';
import { paperBg, paperBorder } from '../paperSurface';
import SourcesLeaderboard from './SourcesLeaderboard';
import SourcesOverlap from './SourcesOverlap';
import CollectionGaps from './CollectionGaps';
import SourceRecommendations from './SourceRecommendations';
import SourceIntelligenceSettings from './SourceIntelligenceSettings';
import { SourceIntelligenceStatusQuery } from './__generated__/SourceIntelligenceStatusQuery.graphql';

export const sourceIntelligenceStatusQuery = graphql`
  query SourceIntelligenceStatusQuery {
    sourceIntelligenceStatus {
      manager_running
      enterprise_edition
      provenance_mode
      pulse_available
      hunt_available
      sources_count
      last_full_run_start
      last_full_run_end
      last_run_success
      last_run_message
      last_scanned_objects
      last_scan_truncated
      backfill_done
      backfill_next_day
      recompute_requested_at
    }
  }
`;

const sourceIntelligenceRecomputeMutation = graphql`
  mutation SourceIntelligenceRecomputeMutation {
    sourceIntelligenceRecompute
  }
`;

const sourceIntelligenceDashboardCreateMutation = graphql`
  mutation SourceIntelligenceDashboardCreateMutation($name: String) {
    sourceIntelligenceDashboardCreate(name: $name) {
      id
    }
  }
`;

export type SourceIntelligenceView = 'leaderboard' | 'overlap' | 'gaps' | 'recommendations' | 'settings';
const SOURCE_INTELLIGENCE_VIEWS: SourceIntelligenceView[] = ['leaderboard', 'overlap', 'gaps', 'recommendations', 'settings'];

interface SourceIntelligenceHeaderProps {
  queryRef: PreloadedQuery<SourceIntelligenceStatusQuery>;
}

const SourceIntelligenceHeader = ({ queryRef }: SourceIntelligenceHeaderProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const surfaceTheme = useTheme();
  const navigate = useNavigate();
  const { sourceIntelligenceStatus: status } = usePreloadedQuery(sourceIntelligenceStatusQuery, queryRef);
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const canCreateDashboard = useGranted([EXPLORE_EXUPDATE]);
  const [recomputeRequested, setRecomputeRequested] = useState(false);
  const [commitRecompute, recomputing] = useApiMutation(sourceIntelligenceRecomputeMutation, undefined, {
    successMessage: t_i18n('The scorecards will be recomputed in the next minutes'),
  });
  const [commitDashboard, creatingDashboard] = useApiMutation(sourceIntelligenceDashboardCreateMutation);

  const handleRecompute = () => {
    commitRecompute({ variables: {}, onCompleted: () => setRecomputeRequested(true) });
  };
  const handleCreateDashboard = () => {
    commitDashboard({
      variables: { name: t_i18n('Intelligence ROI') },
      onCompleted: (response) => {
        const created = (response as { sourceIntelligenceDashboardCreate?: { id: string } | null }).sourceIntelligenceDashboardCreate;
        if (created?.id) {
          navigate(`/dashboard/workspaces/dashboards/${created.id}`);
        }
      },
    });
  };

  const isPending = recomputeRequested || (!!status.recompute_requested_at
    && (!status.last_full_run_start || status.recompute_requested_at > status.last_full_run_start));
  let runLabel = t_i18n('Never computed');
  if (status.last_full_run_end) {
    runLabel = `${t_i18n('Last computation')}: ${nsdt(status.last_full_run_end)}`;
  }

  return (
    <Box
      sx={{
        borderRadius: 1,
        border: `1px solid ${paperBorder(surfaceTheme)}`,
        backgroundColor: paperBg(surfaceTheme),
        padding: 3,
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2}>
        <Box>
          <Typography variant="h1" sx={{ fontWeight: 700, fontSize: 22, marginBottom: 0.5 }}>
            {t_i18n('Source Intelligence')}
          </Typography>
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary, maxWidth: 760 }}>
            {t_i18n('Measure the operational value of every connector, feed and author: unique contribution, lead time, accuracy, relevance, detection impact, noise and cost.')}
          </Typography>
        </Box>
        <Stack direction="row" gap={1} flexShrink={0}>
          {canCreateDashboard && (
            <Button
              variant="secondary"
              startIcon={<DashboardOutlined />}
              onClick={handleCreateDashboard}
              disabled={creatingDashboard}
              data-testid="source-intelligence-create-dashboard"
            >
              {t_i18n('Create the Intelligence ROI dashboard')}
            </Button>
          )}
          {canManage && (
            <Button
              startIcon={<RefreshOutlined />}
              onClick={handleRecompute}
              disabled={recomputing || isPending || !status.manager_running}
              data-testid="source-intelligence-recompute"
            >
              {isPending ? t_i18n('Recomputation requested') : t_i18n('Recompute')}
            </Button>
          )}
        </Stack>
      </Stack>
      <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center" sx={{ marginTop: 2 }} data-testid="source-intelligence-status">
        <Tag
          label={status.manager_running ? t_i18n('Manager running') : t_i18n('Manager stopped')}
          color={status.manager_running ? theme.palette.success.main : theme.palette.warn.main}
        />
        <Tag
          label={status.provenance_mode === 'assertions' ? t_i18n('Provenance: assertions') : t_i18n('Provenance: creators')}
          tooltipTitle={status.provenance_mode === 'assertions'
            ? t_i18n('Scorecards use the sources recorded on every fact (first and last assertion per source).')
            : t_i18n('Scorecards use the creators and authors of the objects, lead time is approximated.')}
        />
        <Tag label={`${status.sources_count} ${t_i18n('sources')}`} />
        <Tag
          label={runLabel}
          color={status.last_run_success === false ? theme.palette.error.main : undefined}
          tooltipTitle={status.last_run_message ?? undefined}
        />
        {status.last_scan_truncated && (
          <Tag
            label={t_i18n('Scan truncated')}
            color={theme.palette.warn.main}
            tooltipTitle={t_i18n('The number of scanned objects reached the configured maximum, increase it in the settings for exhaustive scorecards.')}
          />
        )}
        {!status.backfill_done && status.backfill_next_day && (
          <Tag label={`${t_i18n('History backfill in progress')} (${status.backfill_next_day})`} />
        )}
        {status.pulse_available && <Tag label={t_i18n('Threat Pulse joined')} />}
      </Stack>
    </Box>
  );
};

interface SourceIntelligenceProps {
  view?: string;
}

const SourceIntelligence = ({ view: forcedView }: SourceIntelligenceProps) => {
  const { view: viewParam } = useParams();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Source Intelligence'));
  const isEnterpriseEdition = useEnterpriseEdition();
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const statusQueryRef = useQueryLoading<SourceIntelligenceStatusQuery>(sourceIntelligenceStatusQuery, {});
  const view = (forcedView ?? viewParam ?? 'leaderboard') as SourceIntelligenceView;

  if (!SOURCE_INTELLIGENCE_VIEWS.includes(view) || (view === 'settings' && !canManage)) {
    return <Navigate to="/dashboard/integrations/sources" replace={true} />;
  }

  const viewLink = (target: SourceIntelligenceView) => (target === 'leaderboard'
    ? '/dashboard/integrations/sources'
    : `/dashboard/integrations/sources/${target}`);

  return (
    <div data-testid="source-intelligence-page">
      <PageContainer withGap style={{ paddingBottom: 50 }}>
        <Breadcrumbs
          elements={[
            { label: t_i18n('Integrations'), link: '/dashboard/integrations' },
            { label: t_i18n('Sources'), current: true },
          ]}
          noMargin
        />
        <Tabs value="sources" panels="external">
          <TabsList>
            <TabsTrigger value="deployed" asChild>
              <Link to="/dashboard/integrations/deployed">{t_i18n('Deployed')}</Link>
            </TabsTrigger>
            <TabsTrigger value="available" asChild>
              <Link to="/dashboard/integrations/available">{t_i18n('Available')}</Link>
            </TabsTrigger>
            <TabsTrigger value="sources" asChild>
              <Link to="/dashboard/integrations/sources" data-testid="integrations-tab-sources">{t_i18n('Sources')}</Link>
            </TabsTrigger>
          </TabsList>
        </Tabs>
        {statusQueryRef && (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <SourceIntelligenceHeader queryRef={statusQueryRef} />
          </Suspense>
        )}
        <Tabs value={view} panels="external">
          <TabsList>
            <TabsTrigger value="leaderboard" asChild>
              <Link to={viewLink('leaderboard')} data-testid="source-intelligence-tab-leaderboard">{t_i18n('Leaderboard')}</Link>
            </TabsTrigger>
            <TabsTrigger value="overlap" asChild>
              <Link to={viewLink('overlap')} data-testid="source-intelligence-tab-overlap">{t_i18n('Overlap')}</Link>
            </TabsTrigger>
            <TabsTrigger value="gaps" asChild>
              <Link to={viewLink('gaps')} data-testid="source-intelligence-tab-gaps">
                <Stack direction="row" alignItems="center" gap={0.5} component="span">
                  {t_i18n('Collection gaps')}
                  {!isEnterpriseEdition && <EEChip />}
                </Stack>
              </Link>
            </TabsTrigger>
            <TabsTrigger value="recommendations" asChild>
              <Link to={viewLink('recommendations')} data-testid="source-intelligence-tab-recommendations">
                <Stack direction="row" alignItems="center" gap={0.5} component="span">
                  {t_i18n('Recommendations')}
                  {!isEnterpriseEdition && <EEChip />}
                </Stack>
              </Link>
            </TabsTrigger>
            {canManage && (
              <TabsTrigger value="settings" asChild>
                <Link to={viewLink('settings')} data-testid="source-intelligence-tab-settings">{t_i18n('Settings')}</Link>
              </TabsTrigger>
            )}
          </TabsList>
        </Tabs>
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          {view === 'leaderboard' && <SourcesLeaderboard />}
          {view === 'overlap' && <SourcesOverlap />}
          {view === 'gaps' && <CollectionGaps />}
          {view === 'recommendations' && <SourceRecommendations />}
          {view === 'settings' && <SourceIntelligenceSettings />}
        </Suspense>
      </PageContainer>
    </div>
  );
};

export default SourceIntelligence;
