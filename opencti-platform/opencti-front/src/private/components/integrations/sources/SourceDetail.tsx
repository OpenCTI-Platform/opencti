import React, { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, useParams } from 'react-router';
import Grid from '@mui/material/Grid2';
import { Box, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch } from '@filigran/design-system';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import Chart from '@components/common/charts/Chart';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { INGESTION_SETINGESTIONS, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import type { Theme } from '../../../../components/Theme';
import SourcePeriodSelect from './SourcePeriodSelect';
import SourceCostEditor from './SourceCostEditor';
import { SourceKindIcon, ValueScoreBar } from './SourcesLeaderboard';
import { SourceRecommendationsList, sourceRecommendationsQuery } from './SourceRecommendations';
import {
  buildTrendSerie,
  COST_PERIOD_LABELS,
  formatCost,
  formatCount,
  formatHours,
  formatMetric,
  formatRatio,
  formatScore,
  REFERENCE_SCORECARD_PERIOD,
  ScorecardMetricType,
  ScorecardPeriod,
  scoreLevel,
  SOURCE_KIND_LABELS,
} from './sourceIntelligenceUtils';
import { SourceDetailQuery } from './__generated__/SourceDetailQuery.graphql';
import { SourceRecommendationsQuery } from './__generated__/SourceRecommendationsQuery.graphql';

const sourceDetailQuery = graphql`
  query SourceDetailQuery($id: ID!, $period: SourceScorecardPeriod, $trendStart: DateTime) {
    source(id: $id) {
      id
      name
      description
      source_kind
      ref_id
      ref_type
      enabled
      quarantined
      quarantine_draft_id
      tags
      last_computed_at
      cost {
        amount
        currency
        period
      }
      owner {
        id
        name
      }
      connector {
        id
        name
        active
      }
      recommendationsCount(status: [proposed])
      scorecard(period: $period) {
        id
        period
        period_start
        period_end
        computed_at
        provenance_mode
        volume_total
        volume_entities
        volume_relationships
        volume_indicators
        volume_observables
        new_objects
        volume_last_day
        unique_count
        unique_contribution
        corroborated_count
        corroboration_rate
        shared_count
        lead_time_hours
        first_reporter_share
        evaluated_count
        revoked_count
        negative_sightings_count
        false_positive_count
        decay_excluded_count
        accuracy
        pir_matched_count
        relevance
        sightings_count
        security_platform_sightings_count
        hunt_true_positives_count
        incidents_count
        impact_score
        unreferenced_count
        unsighted_count
        expired_count
        noise_count
        noise
        last_asserted_at
        freshness_hours
        median_latency_hours
        actionable_count
        cost_per_actionable_object
        cost_currency
        community_known_count
        community_uniqueness
        value_score
        overlap {
          source_id
          shared_count
          share
          source {
            id
            name
          }
        }
      }
    }
    sourceScorecards(sourceId: $id, period: $period, startDate: $trendStart, first: 400) {
      snapshot_date
      is_live
      value_score
      volume_total
      unique_contribution
      corroboration_rate
      lead_time_hours
      accuracy
      relevance
      impact_score
      noise
      freshness_hours
      cost_per_actionable_object
    }
  }
`;

const sourceDetailEnableMutation = graphql`
  mutation SourceDetailEnableMutation($id: ID!, $input: [EditInput!]!) {
    sourceFieldPatch(id: $id, input: $input) {
      id
      enabled
    }
  }
`;

const TREND_METRICS: Array<{ key: string; label: string; type: ScorecardMetricType }> = [
  { key: 'value_score', label: 'Operational value score', type: 'score' },
  { key: 'volume_total', label: 'Volume', type: 'count' },
  { key: 'unique_contribution', label: 'Unique contribution', type: 'ratio' },
  { key: 'corroboration_rate', label: 'Corroboration rate', type: 'ratio' },
  { key: 'lead_time_hours', label: 'Lead time (hours)', type: 'hours' },
  { key: 'accuracy', label: 'Accuracy', type: 'ratio' },
  { key: 'relevance', label: 'Relevance', type: 'ratio' },
  { key: 'impact_score', label: 'Impact score', type: 'score' },
  { key: 'noise', label: 'Noise', type: 'ratio' },
  { key: 'cost_per_actionable_object', label: 'Cost per actionable object', type: 'cost' },
];
const TREND_DAYS = 90;

interface MetricTileProps {
  label: string;
  value: string;
  hint?: string;
  level?: ReturnType<typeof scoreLevel>;
  testId?: string;
}

const MetricTile = ({ label, value, hint, level = 'unknown', testId }: MetricTileProps) => {
  const theme = useTheme<Theme>();
  const colors = {
    good: theme.palette.success.main,
    average: theme.palette.warn.main,
    poor: theme.palette.error.main,
    unknown: theme.palette.text.primary,
  };
  return (
    <Card padding="small" fullHeight>
      <Stack gap={0.5} data-testid={testId}>
        <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{label}</Typography>
        <Typography sx={{ fontSize: 24, fontWeight: 700, color: colors[level] }}>{value}</Typography>
        {hint && <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{hint}</Typography>}
      </Stack>
    </Card>
  );
};

const BreakdownList = ({ rows }: { rows: Array<[string, string]> }) => {
  const theme = useTheme<Theme>();
  return (
    <Box component="dl" sx={{ margin: 0, display: 'grid', gridTemplateColumns: '1fr max-content', rowGap: 1 }}>
      {rows.map(([label, value]) => (
        <React.Fragment key={label}>
          <Typography component="dt" variant="body2" sx={{ color: theme.palette.text.secondary }}>{label}</Typography>
          <Typography component="dd" variant="body2" sx={{ margin: 0, fontWeight: 600, textAlign: 'right' }}>{value}</Typography>
        </React.Fragment>
      ))}
    </Box>
  );
};

// Enterprise Edition only: the recommendations API rejects Community Edition platforms, so the query is never sent there
const SourceRecommendationsSection = ({ sourceId }: { sourceId: string }) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<SourceRecommendationsQuery>(
    sourceRecommendationsQuery,
    { count: 10, sourceId, status: ['proposed', 'applied', 'failed'] },
  );
  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <SourceRecommendationsList queryRef={queryRef} hideSource emptyMessage={t_i18n('No pending recommendation for this source.')} />
    </Suspense>
  );
};

interface SourceDetailComponentProps {
  queryRef: PreloadedQuery<SourceDetailQuery>;
  period: ScorecardPeriod;
  onPeriodChange: (period: ScorecardPeriod) => void;
}

const SourceDetailComponent = ({ queryRef, period, onPeriodChange }: SourceDetailComponentProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const { setTitle } = useConnectedDocumentModifier();
  const isEnterpriseEdition = useEnterpriseEdition();
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const { source, sourceScorecards } = usePreloadedQuery(sourceDetailQuery, queryRef);
  const [trendMetric, setTrendMetric] = useState('value_score');
  const [commitEnable] = useApiMutation(sourceDetailEnableMutation);
  const trendDefinition = TREND_METRICS.find((metric) => metric.key === trendMetric) ?? TREND_METRICS[0];
  const trendSeries = useMemo(() => [{
    name: t_i18n(trendDefinition.label),
    data: buildTrendSerie(sourceScorecards, trendDefinition.key, trendDefinition.type),
  }], [sourceScorecards, trendDefinition]);
  const trendOptions: ApexOptions = useMemo(() => ({
    chart: { type: 'line', background: 'transparent', foreColor: theme.palette.text.secondary, toolbar: { show: false }, zoom: { enabled: false } },
    theme: { mode: theme.palette.mode },
    colors: [theme.palette.primary.main],
    stroke: { curve: 'smooth', width: 2 },
    markers: { size: 0 },
    grid: { borderColor: theme.palette.divider },
    dataLabels: { enabled: false },
    xaxis: { type: 'datetime', labels: { datetimeUTC: false } },
    yaxis: { labels: { formatter: (value: number) => (trendDefinition.type === 'ratio' ? `${value.toFixed(0)} %` : formatMetric(value, trendDefinition.type)) } },
    tooltip: { theme: theme.palette.mode, x: { format: 'yyyy-MM-dd' } },
  }), [theme, trendDefinition]);

  if (!source) {
    return <ErrorNotFound />;
  }
  setTitle(`${source.name} | ${t_i18n('Source Intelligence')}`);
  const scorecard = source.scorecard;
  const currency = scorecard?.cost_currency ?? source.cost?.currency;

  return (
    <div data-testid="source-detail-page">
      <PageContainer withGap style={{ paddingBottom: 50 }}>
        <Breadcrumbs
          elements={[
            { label: t_i18n('Integrations'), link: '/dashboard/integrations' },
            { label: t_i18n('Sources'), link: '/dashboard/integrations/sources' },
            { label: source.name, current: true },
          ]}
          noMargin
        />
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2}>
          <Box sx={{ minWidth: 0 }}>
            <Stack direction="row" gap={1} alignItems="center">
              <SourceKindIcon kind={source.source_kind} />
              <Typography variant="h1" sx={{ fontWeight: 700, fontSize: 22, margin: 0 }}>{source.name}</Typography>
            </Stack>
            <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginTop: 1 }}>
              <Tag label={t_i18n(SOURCE_KIND_LABELS[source.source_kind] ?? source.source_kind)} />
              {source.quarantined && <Tag label={t_i18n('Quarantined')} color={theme.palette.warn.main} />}
              {(source.tags ?? []).map((tag) => <Tag key={tag} label={tag} size="small" />)}
              {source.connector && (
                <Link to={`/dashboard/integrations/connectors/${source.connector.id}`}>
                  {`${t_i18n('Connector health and logs')}: ${source.connector.name}`}
                </Link>
              )}
              {source.quarantined && source.quarantine_draft_id && (
                <Link to={`/dashboard/data/import/draft/${source.quarantine_draft_id}`}>{t_i18n('Quarantine draft')}</Link>
              )}
            </Stack>
            {source.description && (
              <Typography variant="body2" sx={{ marginTop: 1, color: theme.palette.text.secondary }}>{source.description}</Typography>
            )}
          </Box>
          <Stack direction="row" gap={2} alignItems="center" flexShrink={0}>
            {canManage && (
              <Switch
                checked={source.enabled}
                onCheckedChange={(checked) => commitEnable({ variables: { id: source.id, input: [{ key: 'enabled', value: [String(checked)] }] } })}
                label={t_i18n('Scored')}
                data-testid="source-enabled-switch"
              />
            )}
            {canManage && <SourceCostEditor sourceId={source.id} cost={source.cost} />}
            <SourcePeriodSelect value={period} onChange={onPeriodChange} />
          </Stack>
        </Stack>
        {!scorecard ? (
          <Card>
            <Typography variant="body2" data-testid="source-detail-no-scorecard">
              {t_i18n('This source has no scorecard for this period yet. Scorecards are computed every night and after a recomputation request.')}
            </Typography>
          </Card>
        ) : (
          <>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card padding="small" fullHeight>
                  <Stack gap={1} data-testid="source-detail-value-score">
                    <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{t_i18n('Operational value score')}</Typography>
                    <Typography sx={{ fontSize: 40, fontWeight: 700 }}>{formatScore(scorecard.value_score)}</Typography>
                    <ValueScoreBar value={scorecard.value_score} />
                    <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                      {`${t_i18n('Computed')} ${nsdt(scorecard.computed_at)} - ${scorecard.provenance_mode === 'assertions' ? t_i18n('Provenance: assertions') : t_i18n('Provenance: creators')}`}
                    </Typography>
                  </Stack>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 8 }}>
                <Grid container spacing={2}>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Volume')} value={formatCount(scorecard.volume_total)} hint={`${formatCount(scorecard.new_objects)} ${t_i18n('new')}`} testId="source-metric-volume" />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Unique contribution')} value={formatRatio(scorecard.unique_contribution)} level={scoreLevel(scorecard.unique_contribution)} hint={`${formatCount(scorecard.unique_count)} ${t_i18n('unique objects')}`} />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Corroboration rate')} value={formatRatio(scorecard.corroboration_rate)} level={scoreLevel(scorecard.corroboration_rate)} />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Lead time')}
                      value={formatHours(scorecard.lead_time_hours)}
                      hint={scorecard.first_reporter_share !== null && scorecard.first_reporter_share !== undefined
                        ? `${formatRatio(scorecard.first_reporter_share, 0)} ${t_i18n('reported first')}`
                        : t_i18n('No shared object')}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Accuracy')} value={formatRatio(scorecard.accuracy)} level={scoreLevel(scorecard.accuracy)} hint={`${formatCount(scorecard.evaluated_count)} ${t_i18n('evaluated')}`} />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Relevance')}
                      value={isEnterpriseEdition ? formatRatio(scorecard.relevance) : t_i18n('Enterprise Edition')}
                      level={isEnterpriseEdition ? scoreLevel(scorecard.relevance) : 'unknown'}
                      hint={isEnterpriseEdition ? `${formatCount(scorecard.pir_matched_count)} ${t_i18n('in a PIR')}` : undefined}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Impact')} value={formatScore(scorecard.impact_score)} level={scoreLevel(scorecard.impact_score, { scale: 100 })} hint={`${formatCount(scorecard.sightings_count)} ${t_i18n('sightings')}`} />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Noise')} value={formatRatio(scorecard.noise)} level={scoreLevel(scorecard.noise, { higherIsBetter: false })} />
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 8 }}>
                <Card
                  title={t_i18n('Trend')}
                  action={(
                    <Select value={trendMetric} onValueChange={setTrendMetric}>
                      <SelectTrigger aria-label={t_i18n('Metric')} data-testid="source-trend-metric">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent aria-label={t_i18n('Metric')}>
                        {TREND_METRICS.filter((metric) => isEnterpriseEdition || metric.key !== 'relevance').map((metric) => (
                          <SelectItem key={metric.key} value={metric.key}>{t_i18n(metric.label)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                >
                  <Box sx={{ height: 280 }} data-testid="source-detail-trend">
                    {trendSeries[0].data.length > 0 ? (
                      <Chart options={trendOptions} series={trendSeries} type="line" width="100%" height="100%" />
                    ) : (
                      <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                        {t_i18n('No daily snapshot yet: the trend appears after the first nightly computations or once the history backfill is done.')}
                      </Typography>
                    )}
                  </Box>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card title={t_i18n('Cost and freshness')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Declared cost'), source.cost ? `${source.cost.amount} ${source.cost.currency} - ${t_i18n(COST_PERIOD_LABELS[source.cost.period] ?? source.cost.period)}` : t_i18n('None')],
                    [t_i18n('Actionable objects'), formatCount(scorecard.actionable_count)],
                    [t_i18n('Cost per actionable object'), formatCost(scorecard.cost_per_actionable_object, currency)],
                    [t_i18n('Last assertion'), scorecard.last_asserted_at ? nsdt(scorecard.last_asserted_at) : '-'],
                    [t_i18n('Time since last assertion'), formatHours(scorecard.freshness_hours)],
                    [t_i18n('Median publication latency'), formatHours(scorecard.median_latency_hours)],
                    [t_i18n('Community uniqueness'), formatRatio(scorecard.community_uniqueness)],
                  ]}
                  />
                </Card>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Volume')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Entities'), formatCount(scorecard.volume_entities)],
                    [t_i18n('Relationships'), formatCount(scorecard.volume_relationships)],
                    [t_i18n('Indicators'), formatCount(scorecard.volume_indicators)],
                    [t_i18n('Observables'), formatCount(scorecard.volume_observables)],
                    [t_i18n('Last 24 hours'), formatCount(scorecard.volume_last_day)],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Accuracy')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Revoked'), formatCount(scorecard.revoked_count)],
                    [t_i18n('Negative sightings'), formatCount(scorecard.negative_sightings_count)],
                    [t_i18n('False positives'), formatCount(scorecard.false_positive_count)],
                    [t_i18n('Decay exclusions'), formatCount(scorecard.decay_excluded_count)],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Impact')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Sightings'), formatCount(scorecard.sightings_count)],
                    [t_i18n('Security platform sightings'), formatCount(scorecard.security_platform_sightings_count)],
                    [t_i18n('Hunt true positives'), formatCount(scorecard.hunt_true_positives_count)],
                    [t_i18n('Incidents referencing'), formatCount(scorecard.incidents_count)],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Noise')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Never referenced'), formatCount(scorecard.unreferenced_count)],
                    [t_i18n('Never sighted'), formatCount(scorecard.unsighted_count)],
                    [t_i18n('Expired'), formatCount(scorecard.expired_count)],
                    [t_i18n('Noisy objects'), formatCount(scorecard.noise_count)],
                  ]}
                  />
                </Card>
              </Grid>
            </Grid>
            <Card title={t_i18n('Top overlapping sources')}>
              {scorecard.overlap.length === 0 ? (
                <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>{t_i18n('No other source asserted the objects of this source.')}</Typography>
              ) : (
                <Stack gap={1} data-testid="source-detail-overlap">
                  {scorecard.overlap.map((share) => (
                    <Stack key={share.source_id} direction="row" gap={2} alignItems="center">
                      <Box sx={{ width: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {share.source
                          ? <Link to={`/dashboard/integrations/sources/source/${share.source.id}`}>{share.source.name}</Link>
                          : t_i18n('Restricted')}
                      </Box>
                      <Box sx={{ flex: 1 }}><ValueScoreBar value={share.share * 100} /></Box>
                      <Typography variant="caption" sx={{ width: 140, textAlign: 'right' }}>{`${formatCount(share.shared_count)} ${t_i18n('shared objects')}`}</Typography>
                    </Stack>
                  ))}
                </Stack>
              )}
            </Card>
          </>
        )}
        <Card title={t_i18n('Recommendations')}>
          {!isEnterpriseEdition && (
            <Typography variant="body2">{t_i18n('Recommendations and autonomous tuning are available with the Enterprise Edition.')}</Typography>
          )}
          {isEnterpriseEdition && <SourceRecommendationsSection sourceId={source.id} />}
        </Card>
      </PageContainer>
    </div>
  );
};

const SourceDetail = () => {
  const { sourceId } = useParams() as { sourceId: string };
  const [period, setPeriod] = useState<ScorecardPeriod>(REFERENCE_SCORECARD_PERIOD);
  const trendStart = useMemo(() => new Date(Date.now() - TREND_DAYS * 24 * 3600 * 1000).toISOString(), []);
  const queryRef = useQueryLoading<SourceDetailQuery>(sourceDetailQuery, { id: sourceId, period, trendStart });
  if (!queryRef) {
    return <Loader variant={LoaderVariant.container} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <SourceDetailComponent queryRef={queryRef} period={period} onPeriodChange={setPeriod} />
    </Suspense>
  );
};

export default SourceDetail;
