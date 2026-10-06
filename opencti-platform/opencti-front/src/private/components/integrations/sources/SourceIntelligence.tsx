import React, { Suspense, useState } from 'react';
import { Link, Navigate, useNavigate, useParams } from 'react-router';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Skeleton, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import {
  Alert,
  Chip,
  type ChipSeverity,
  Hero,
  HeroBody,
  HeroHeader,
  ProgressBar,
  Tabs,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import { DashboardOutlined, RefreshOutlined, SettingsOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';
import { IntegrationsSourcesChrome } from '../Integrations';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import notifyMutationOutcome from './notifyMutationOutcome';
import useGranted, { EXPLORE_EXUPDATE, INGESTION_SETINGESTIONS, MODULES_MODMANAGE, SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Theme } from '../../../../components/Theme';
import { paperBg, paperBorder } from '../paperSurface';
import SourcesLeaderboard from './SourcesLeaderboard';
import SourcesOverlap from './SourcesOverlap';
import CollectionGaps from './CollectionGaps';
import SourceRecommendations from './SourceRecommendations';
import { SOURCE_INTELLIGENCE_DOCUMENTATION_URL, SOURCE_INTELLIGENCE_MANAGER_DOCUMENTATION_URL, SOURCE_INTELLIGENCE_SETTINGS_PATH } from './sourceIntelligenceUtils';
import SourceIntelligenceKpis, { QUARANTINED_SOURCES_FILTERS, sourceIntelligenceKpisQuery, SourceIntelligenceKpisSkeleton } from './SourceIntelligenceKpis';
import { SourceIntelligenceStatusQuery } from './__generated__/SourceIntelligenceStatusQuery.graphql';
import { SourceIntelligenceKpisQuery } from './__generated__/SourceIntelligenceKpisQuery.graphql';

export const sourceIntelligenceStatusQuery = graphql`
  query SourceIntelligenceStatusQuery {
    sourceIntelligenceStatus {
      manager_enabled
      manager_running
      enterprise_edition
      sources_count
      scored_sources_count
      last_full_run_start
      last_full_run_end
      last_run_success
      last_run_message
      last_scanned_objects
      last_scan_truncated
      backfill_done
      backfill_next_day
      backfill_days_done
      backfill_days_total
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

export type SourceIntelligenceView = 'leaderboard' | 'overlap' | 'gaps' | 'recommendations';
const SOURCE_INTELLIGENCE_VIEWS: SourceIntelligenceView[] = ['leaderboard', 'overlap', 'gaps', 'recommendations'];

type RunState = 'disabled' | 'stopped' | 'requested' | 'running' | 'failed' | 'never' | 'ok';

const RUN_STATES: Record<RunState, { label: string; severity: ChipSeverity }> = {
  disabled: { label: 'Manager disabled', severity: 'medium' },
  stopped: { label: 'Manager stopped', severity: 'medium' },
  requested: { label: 'Recompute requested', severity: 'info' },
  running: { label: 'Computing', severity: 'info' },
  failed: { label: 'Failed', severity: 'high' },
  never: { label: 'Not computed yet', severity: 'neutral' },
  ok: { label: 'Up to date', severity: 'low' },
};

export const sourceIntelligenceRunState = (
  status: Pick<SourceIntelligenceStatusQuery['response']['sourceIntelligenceStatus'], 'manager_enabled' | 'manager_running' | 'last_full_run_start' | 'last_full_run_end' | 'last_run_success'>,
  recomputePending: boolean,
): RunState => {
  if (!status.manager_enabled) return 'disabled';
  if (!status.manager_running) return 'stopped';
  if (status.last_full_run_start && (!status.last_full_run_end || status.last_full_run_start > status.last_full_run_end)) return 'running';
  if (recomputePending) return 'requested';
  if (!status.last_full_run_end) return 'never';
  return status.last_run_success === false ? 'failed' : 'ok';
};

interface SourceIntelligenceHeaderProps {
  queryRef: PreloadedQuery<SourceIntelligenceStatusQuery>;
}

const SourceIntelligenceHeader = ({ queryRef }: SourceIntelligenceHeaderProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const theme = useTheme<Theme>();
  const surfaceTheme = useTheme();
  const navigate = useNavigate();
  const { sourceIntelligenceStatus: status } = usePreloadedQuery(sourceIntelligenceStatusQuery, queryRef);
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const canCreateDashboard = useGranted([EXPLORE_EXUPDATE]);
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const [recomputeRequested, setRecomputeRequested] = useState(false);
  const [commitRecompute, recomputing] = useApiMutation(sourceIntelligenceRecomputeMutation);
  const [commitDashboard, creatingDashboard] = useApiMutation(sourceIntelligenceDashboardCreateMutation);

  const handleRecompute = () => {
    commitRecompute({
      variables: {},
      onCompleted: (_, errors) => {
        if (notifyMutationOutcome(errors, { success: t_i18n('The scorecards will be recomputed in the next minutes') })) {
          setRecomputeRequested(true);
        }
      },
    });
  };
  const handleCreateDashboard = () => {
    commitDashboard({
      variables: { name: t_i18n('Intelligence ROI') },
      onCompleted: (response, errors) => {
        if (!notifyMutationOutcome(errors)) return;
        const created = (response as { sourceIntelligenceDashboardCreate?: { id: string } | null }).sourceIntelligenceDashboardCreate;
        if (created?.id) {
          navigate(`/dashboard/workspaces/dashboards/${created.id}`);
        }
      },
    });
  };

  const isPending = recomputeRequested || (!!status.recompute_requested_at
    && (!status.last_full_run_start || status.recompute_requested_at > status.last_full_run_start));
  const runState = sourceIntelligenceRunState(status, isPending);
  const { label: stateLabel, severity: stateSeverity } = RUN_STATES[runState];
  const statusSentence = {
    disabled: t_i18n('The source intelligence manager is disabled in the platform configuration, so the scorecards are not computed. An administrator of the platform deployment can enable it.'),
    stopped: t_i18n('The source intelligence manager is not running, so the scorecards are not refreshed.'),
    requested: t_i18n('A computation of the scorecards starts in the next minutes.'),
    running: t_i18n('The scorecards are being computed, started {time}.', { values: { time: rd(status.last_full_run_start) } }),
    failed: t_i18n('The last computation of the scorecards failed {time}.', { values: { time: rd(status.last_full_run_end) } }),
    never: t_i18n('The scorecards have not been computed yet. They are computed every day, or now on request.'),
    ok: t_i18n('The scorecards of {count, plural, one {# source} other {# sources}} were refreshed {time}.', {
      values: { count: status.sources_count, time: rd(status.last_full_run_end) },
    }),
  }[runState];
  const statusDate = runState === 'running' ? status.last_full_run_start : status.last_full_run_end;
  const recomputeLabel = {
    failed: t_i18n('Retry the computation'),
    never: t_i18n('Compute now'),
  }[runState as 'failed' | 'never'] ?? t_i18n('Recompute');
  const showRecompute = canManage && ['ok', 'failed', 'never'].includes(runState);
  const backfillTotal = status.backfill_days_total ?? 0;
  const backfillLabel = !status.backfill_done && backfillTotal > 0
    ? t_i18n('Backfilling history - {done} of {total, plural, one {# day} other {# days}}', { values: { done: status.backfill_days_done ?? 0, total: backfillTotal } })
    : null;

  return (
    <Box
      component="section"
      aria-labelledby="source-intelligence-title"
      sx={{
        borderRadius: 1,
        border: `1px solid ${paperBorder(surfaceTheme)}`,
        backgroundColor: paperBg(surfaceTheme),
        padding: 3,
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2} flexWrap="wrap">
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography id="source-intelligence-title" variant="h1" sx={{ marginBottom: 0.5 }}>
            {t_i18n('Source Intelligence')}
          </Typography>
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary }} noWrap>
            {t_i18n('Measure the operational value of every connector, feed and author.')}
            {' '}
            <a href={SOURCE_INTELLIGENCE_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Learn more')}</a>
          </Typography>
        </Box>
        <Stack direction="row" gap={1} flexShrink={0} flexWrap="wrap">
          {canCreateDashboard && (
            <Button
              variant="secondary"
              startIcon={<DashboardOutlined />}
              onClick={handleCreateDashboard}
              disabled={creatingDashboard}
              data-testid="source-intelligence-create-dashboard"
            >
              {t_i18n('Create ROI dashboard')}
            </Button>
          )}
          {canCustomize && (
            <Button
              variant={runState === 'stopped' ? undefined : 'secondary'}
              startIcon={<SettingsOutlined />}
              component={Link}
              to={SOURCE_INTELLIGENCE_SETTINGS_PATH}
              data-testid="source-intelligence-settings"
            >
              {t_i18n('Open settings')}
            </Button>
          )}
          {showRecompute && (
            <Button
              startIcon={<RefreshOutlined />}
              onClick={handleRecompute}
              disabled={recomputing}
              data-testid="source-intelligence-recompute"
            >
              {recomputeLabel}
            </Button>
          )}
        </Stack>
      </Stack>
      <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginTop: 2 }} data-testid="source-intelligence-status">
        <Chip severity={stateSeverity} size="sm" label={t_i18n(stateLabel)} />
        {statusDate ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Typography variant="body2" aria-live="polite" tabIndex={0}>{statusSentence}</Typography>
            </TooltipTrigger>
            <TooltipContent>{fldt(statusDate)}</TooltipContent>
          </Tooltip>
        ) : (
          <Typography variant="body2" aria-live="polite">{statusSentence}</Typography>
        )}
        {runState === 'disabled' && (
          <Button
            variant="tertiary"
            size="small"
            component="a"
            href={SOURCE_INTELLIGENCE_MANAGER_DOCUMENTATION_URL}
            target="_blank"
            rel="noopener noreferrer"
            data-testid="source-intelligence-manager-documentation"
          >
            {t_i18n('Read the documentation')}
          </Button>
        )}
      </Stack>
      <Typography variant="caption" component="p" sx={{ color: theme.palette.text.secondary, marginTop: 0.5, marginBottom: 0 }}>
        {t_i18n('Attribution from creators and authors, lead time approximated')}
      </Typography>
      {backfillLabel && (
        <Stack gap={0.5} sx={{ marginTop: 1.5, maxWidth: 420 }} data-testid="source-intelligence-backfill">
          <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{backfillLabel}</Typography>
          <ProgressBar value={Math.round(((status.backfill_days_done ?? 0) / backfillTotal) * 100)} aria-label={backfillLabel} />
        </Stack>
      )}
      {runState === 'failed' && (
        <Box sx={{ marginTop: 2 }}>
          <Alert
            severity="error"
            title={t_i18n('The scorecards could not be computed.')}
            description={status.last_run_message ?? t_i18n('The platform logs of the source intelligence manager give the cause.')}
          />
        </Box>
      )}
      {status.last_scan_truncated && (
        <Box sx={{ marginTop: 2 }}>
          <Alert
            severity="warning"
            title={t_i18n('The scorecards cover the first {count, plural, one {# object} other {# objects}} only.', { values: { count: status.last_scanned_objects ?? 0 } })}
            description={status.enterprise_edition
              ? t_i18n('The scan reached the maximum number of objects set in the settings. Recommendations are not refreshed until a computation covers every object.')
              : t_i18n('The scan reached the maximum number of objects set in the settings.')}
            action={canCustomize ? (
              <Button variant="secondary" size="small" component={Link} to={SOURCE_INTELLIGENCE_SETTINGS_PATH}>
                {t_i18n('Raise the limit')}
              </Button>
            ) : undefined}
          />
        </Box>
      )}
    </Box>
  );
};

export const SourceIntelligenceHeaderSkeleton = () => (
  <Skeleton variant="rounded" height={148} aria-hidden data-testid="source-intelligence-header-loading" />
);

// First use: what feeds the scorecards, how to get the first ones and where to read more
const SourceIntelligenceFirstUse = ({ queryRef }: SourceIntelligenceHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { sourceIntelligenceStatus: status } = usePreloadedQuery(sourceIntelligenceStatusQuery, queryRef);
  // Every tracked source gets scorecards: the first use lasts until one of them counts knowledge
  if (status.scored_sources_count > 0) {
    return null;
  }
  return (
    <Hero data-testid="source-intelligence-first-use">
      <HeroHeader
        action={(
          <Button variant="secondary" component="a" href={SOURCE_INTELLIGENCE_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
            {t_i18n('Read the documentation')}
          </Button>
        )}
      >
        <Typography variant="h2" sx={{ margin: 0 }}>{t_i18n('No source scored yet')}</Typography>
      </HeroHeader>
      <HeroBody>
        <Typography variant="body2">
          {t_i18n('Every connector, ingestion feed, significant author and analyst writing knowledge becomes a source. Its scorecard appears after the first computation, once it has written knowledge.')}
        </Typography>
      </HeroBody>
    </Hero>
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
  const statusQueryRef = useQueryLoading<SourceIntelligenceStatusQuery>(sourceIntelligenceStatusQuery, {});
  const kpisQueryRef = useQueryLoading<SourceIntelligenceKpisQuery>(sourceIntelligenceKpisQuery, {
    quarantinedFilters: QUARANTINED_SOURCES_FILTERS,
    enterprise: isEnterpriseEdition,
  } as unknown as SourceIntelligenceKpisQuery['variables']);
  const view = (forcedView ?? viewParam ?? 'leaderboard') as SourceIntelligenceView;

  // The settings moved to Settings > Customization
  if ((view as string) === 'settings') {
    return <Navigate to={SOURCE_INTELLIGENCE_SETTINGS_PATH} replace={true} />;
  }
  if (!SOURCE_INTELLIGENCE_VIEWS.includes(view)) {
    return <Navigate to="/dashboard/integrations/sources" replace={true} />;
  }

  const viewLink = (target: SourceIntelligenceView) => (target === 'leaderboard'
    ? '/dashboard/integrations/sources'
    : `/dashboard/integrations/sources/${target}`);

  return (
    <IntegrationsSourcesChrome>
      <Stack gap={3} data-testid="source-intelligence-page">
        {statusQueryRef && (
          <Suspense fallback={<SourceIntelligenceHeaderSkeleton />}>
            <SourceIntelligenceHeader queryRef={statusQueryRef} />
          </Suspense>
        )}
        {kpisQueryRef && (
          <Suspense fallback={<SourceIntelligenceKpisSkeleton />}>
            <SourceIntelligenceKpis queryRef={kpisQueryRef} />
          </Suspense>
        )}
        {statusQueryRef && view === 'leaderboard' && (
          <Suspense fallback={null}>
            <SourceIntelligenceFirstUse queryRef={statusQueryRef} />
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
          </TabsList>
        </Tabs>
        <Suspense fallback={<Skeleton variant="rounded" height={320} aria-hidden />}>
          {view === 'leaderboard' && <SourcesLeaderboard />}
          {view === 'overlap' && <SourcesOverlap />}
          {view === 'gaps' && <CollectionGaps />}
          {view === 'recommendations' && <SourceRecommendations />}
        </Suspense>
      </Stack>
    </IntegrationsSourcesChrome>
  );
};

export default SourceIntelligence;
