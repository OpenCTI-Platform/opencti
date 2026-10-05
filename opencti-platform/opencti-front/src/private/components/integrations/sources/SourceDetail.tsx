import React, { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, useParams, useSearchParams } from 'react-router';
import Grid from '@mui/material/Grid2';
import { Box, Skeleton, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import { Chip, type ChipSeverity, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import Chart from '@components/common/charts/Chart';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
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
  DECLARED_AMOUNT_LABELS,
  formatMetric,
  REFERENCE_SCORECARD_PERIOD,
  ScorecardMetricType,
  ScorecardPeriod,
  scoreLevel,
  SOURCE_EDIT_COST,
  SOURCE_EDIT_PARAM,
  SOURCE_KIND_LABELS,
} from './sourceIntelligenceUtils';
import SourceMetricValue, { RelativeTime, useSourceMetricFormat } from './SourceMetricValue';
import notifyMutationOutcome from './notifyMutationOutcome';
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
      scorecard_date
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
const RECOMMENDATIONS_ANCHOR = 'source-recommendations';

// The daily computation sets the score and the ratios; between two computations only volumes and signals move
const SCORED_WINDOW_SENTENCES: Record<ScorecardPeriod, string> = {
  LAST_7_DAYS: 'Value score and ratios of the last 7 days computed {time}; volumes and signals follow the knowledge since.',
  LAST_30_DAYS: 'Value score and ratios of the last 30 days computed {time}; volumes and signals follow the knowledge since.',
  LAST_90_DAYS: 'Value score and ratios of the last 90 days computed {time}; volumes and signals follow the knowledge since.',
};

interface MetricTileProps {
  label: string;
  value: React.ReactNode;
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
        <Typography variant="h2" component="div" sx={{ margin: 0, color: colors[level] }}>{value}</Typography>
        {hint && <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>{hint}</Typography>}
      </Stack>
    </Card>
  );
};

const BreakdownList = ({ rows }: { rows: Array<[string, React.ReactNode]> }) => {
  const theme = useTheme<Theme>();
  return (
    <Box component="dl" sx={{ margin: 0, display: 'grid', gridTemplateColumns: '1fr max-content', rowGap: 1 }}>
      {rows.map(([label, value]) => (
        <React.Fragment key={label}>
          <Typography component="dt" variant="body2" sx={{ color: theme.palette.text.secondary }}>{label}</Typography>
          <Typography component="dd" variant="body2" sx={{ margin: 0, fontWeight: 'fontWeightMedium', textAlign: 'right' }}>{value}</Typography>
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
    { count: 10, sourceId, status: ['proposed', 'applying', 'applied', 'reverting', 'failed'] },
  );
  if (!queryRef) {
    return <Skeleton variant="rounded" height={96} aria-hidden />;
  }
  return (
    <Suspense fallback={<Skeleton variant="rounded" height={96} aria-hidden />}>
      <SourceRecommendationsList queryRef={queryRef} hideSource emptyMessage={t_i18n('No pending recommendation for this source.')} />
    </Suspense>
  );
};

interface SourceDetailComponentProps {
  queryRef: PreloadedQuery<SourceDetailQuery>;
  period: ScorecardPeriod;
  onPeriodChange: (period: ScorecardPeriod) => void;
}

const SourceDetailSkeleton = () => (
  <Stack gap={2} sx={{ padding: 3 }} aria-hidden data-testid="source-detail-loading">
    <Skeleton variant="rounded" height={88} />
    <Stack direction="row" gap={2}>
      <Skeleton variant="rounded" height={180} sx={{ flex: 1 }} />
      <Skeleton variant="rounded" height={180} sx={{ flex: 2 }} />
    </Stack>
    <Skeleton variant="rounded" height={280} />
  </Stack>
);

const SourceDetailComponent = ({ queryRef, period, onPeriodChange }: SourceDetailComponentProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const format = useSourceMetricFormat();
  const theme = useTheme<Theme>();
  const { setTitle } = useConnectedDocumentModifier();
  const isEnterpriseEdition = useEnterpriseEdition();
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const { source, sourceScorecards } = usePreloadedQuery(sourceDetailQuery, queryRef);
  const [searchParams] = useSearchParams();
  const editCostRequested = searchParams.get(SOURCE_EDIT_PARAM) === SOURCE_EDIT_COST;
  const [trendMetric, setTrendMetric] = useState('value_score');
  const [commitEnable, enableInFlight] = useApiMutation(sourceDetailEnableMutation);
  const handleEnable = (checked: boolean) => {
    if (!source) return;
    commitEnable({
      variables: { id: source.id, input: [{ key: 'enabled', value: [String(checked)] }] },
      onCompleted: (_, errors) => {
        notifyMutationOutcome(errors, {
          success: checked ? t_i18n('The source is scored again from the next computation') : t_i18n('The source is no longer scored'),
        });
      },
    });
  };
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
  const value = (formatted: string | null, reason?: string) => <SourceMetricValue value={formatted} reason={reason} />;
  let sourceState: { label: string; severity: ChipSeverity } = { label: 'Scored', severity: 'low' };
  let sourceStateSentence = scorecard
    ? t_i18n(SCORED_WINDOW_SENTENCES[period], { values: { time: rd(scorecard.computed_at) } })
    : t_i18n('No scorecard for this window yet: it appears after the next computation once the source has written knowledge.');
  let sourceStateDate: string | null | undefined = scorecard?.computed_at;
  if (!source.enabled) {
    sourceState = { label: 'Disabled', severity: 'neutral' };
    sourceStateSentence = t_i18n('Scoring is turned off for this source: its scorecards are not computed.');
    sourceStateDate = null;
  } else if (source.quarantined) {
    sourceState = { label: 'Quarantined', severity: 'medium' };
    sourceStateSentence = t_i18n('The new knowledge of this source goes to a review draft instead of the live knowledge.');
    sourceStateDate = null;
  } else if (!scorecard) {
    sourceState = { label: 'Not scored yet', severity: 'neutral' };
  }
  // Answer first: the score, how it moved over the trend window, and what explains it
  const scoreReference = sourceScorecards.find((point) => !point.is_live && typeof point.value_score === 'number');
  let scoreTrend: { label: string; severity: ChipSeverity } | null = null;
  if (scorecard && typeof scorecard.value_score === 'number' && scoreReference && typeof scoreReference.value_score === 'number') {
    const delta = Math.round(scorecard.value_score - scoreReference.value_score);
    const days = Math.max(1, Math.round((Date.now() - new Date(scoreReference.scorecard_date).getTime()) / (24 * 3600 * 1000)));
    scoreTrend = delta === 0
      ? { label: t_i18n('Stable over {days, plural, one {# day} other {# days}}', { values: { days } }), severity: 'neutral' }
      : {
          label: t_i18n('{delta} in {days, plural, one {# day} other {# days}}', { values: { delta: delta > 0 ? `+${delta}` : String(delta), days } }),
          severity: delta > 0 ? 'low' : 'high',
        };
  }
  let scoreSentence: string | null = null;
  if (scorecard) {
    const shares = (scorecard.shared_count ?? 0) > 0 && typeof scorecard.corroboration_rate === 'number';
    if (shares && typeof scorecard.first_reporter_share === 'number') {
      scoreSentence = t_i18n('Confirmed by other sources on {corroboration} of its objects, and first to report {first} of the objects it shares with them.', {
        values: { corroboration: format.ratio(scorecard.corroboration_rate, 0), first: format.ratio(scorecard.first_reporter_share, 0) },
      });
    } else if (shares) {
      scoreSentence = t_i18n('Confirmed by other sources on {corroboration} of its objects.', { values: { corroboration: format.ratio(scorecard.corroboration_rate, 0) } });
    } else {
      scoreSentence = t_i18n('No other source asserted its objects in this period: the score comes from its volume, accuracy, impact and noise.');
    }
  }
  const pendingRecommendations = isEnterpriseEdition ? (source.recommendationsCount ?? 0) : 0;
  const reviewRecommendations = () => document.getElementById(RECOMMENDATIONS_ANCHOR)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

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
              <Typography variant="h1" sx={{ margin: 0 }}>{source.name}</Typography>
            </Stack>
            <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginTop: 1 }} data-testid="source-detail-status">
              <Chip severity={sourceState.severity} size="sm" label={t_i18n(sourceState.label)} />
              {sourceStateDate ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Typography variant="body2" tabIndex={0}>{sourceStateSentence}</Typography>
                  </TooltipTrigger>
                  <TooltipContent>{fldt(sourceStateDate)}</TooltipContent>
                </Tooltip>
              ) : (
                <Typography variant="body2">{sourceStateSentence}</Typography>
              )}
              {source.quarantined && source.quarantine_draft_id && (
                <Button size="small" component={Link} to={`/dashboard/data/import/draft/${source.quarantine_draft_id}`}>
                  {t_i18n('Open the quarantine draft')}
                </Button>
              )}
            </Stack>
            <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginTop: 1 }}>
              <Tag label={t_i18n(SOURCE_KIND_LABELS[source.source_kind] ?? 'Source')} />
              {(source.tags ?? []).map((tag) => <Tag key={tag} label={tag} size="small" />)}
              {source.connector && (
                <Link to={`/dashboard/integrations/connectors/${source.connector.id}`}>
                  {t_i18n('Connector health and logs: {name}', { values: { name: source.connector.name } })}
                </Link>
              )}
            </Stack>
            {source.description && (
              <Typography variant="body2" sx={{ marginTop: 1, color: theme.palette.text.secondary }}>{source.description}</Typography>
            )}
            {scorecard && (
              <Stack direction="row" gap={1.5} alignItems="center" flexWrap="wrap" sx={{ marginTop: 2 }} data-testid="source-detail-score-summary">
                <Typography variant="h2" component="p" sx={{ margin: 0 }}>
                  {t_i18n('Value score {score} out of 100', { values: { score: format.score(scorecard.value_score) ?? t_i18n('Not measured') } })}
                </Typography>
                {scoreTrend && <Chip severity={scoreTrend.severity} size="sm" label={scoreTrend.label} />}
                {scoreSentence && <Typography variant="body2" sx={{ color: theme.palette.text.secondary, flexBasis: '100%' }}>{scoreSentence}</Typography>}
              </Stack>
            )}
          </Box>
          <Stack direction="row" gap={2} alignItems="center" flexShrink={0} flexWrap="wrap" justifyContent="flex-end">
            <SourcePeriodSelect value={period} onChange={onPeriodChange} />
            {canManage && (
              <Switch
                checked={source.enabled}
                disabled={enableInFlight}
                onCheckedChange={handleEnable}
                label={t_i18n('Scored')}
                data-testid="source-enabled-switch"
              />
            )}
            {canManage && <SourceCostEditor sourceId={source.id} cost={source.cost} primary={pendingRecommendations === 0} initialOpen={editCostRequested} />}
            {pendingRecommendations > 0 && (
              <Button onClick={reviewRecommendations} data-testid="source-detail-review-recommendations">
                {t_i18n('Review {count, plural, one {# recommendation} other {# recommendations}}', { values: { count: pendingRecommendations } })}
              </Button>
            )}
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
                    <Typography variant="h1" component="div" sx={{ margin: 0 }}>{value(format.score(scorecard.value_score))}</Typography>
                    <ValueScoreBar value={scorecard.value_score} />
                    <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                      {scorecard.provenance_mode === 'assertions'
                        ? t_i18n('Attribution from the sources recorded on every fact')
                        : t_i18n('Attribution from creators and authors, lead time approximated')}
                    </Typography>
                  </Stack>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 8 }}>
                <Grid container spacing={2}>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Volume')}
                      value={value(format.count(scorecard.volume_total))}
                      hint={t_i18n('{count, plural, one {# new object} other {# new objects}}', { values: { count: scorecard.new_objects ?? 0 } })}
                      testId="source-metric-volume"
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Unique contribution')}
                      value={value(format.ratio(scorecard.unique_contribution))}
                      level={scoreLevel(scorecard.unique_contribution)}
                      hint={t_i18n('{count, plural, one {# object no other source asserted} other {# objects no other source asserted}}', { values: { count: scorecard.unique_count ?? 0 } })}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Corroboration rate')} value={value(format.ratio(scorecard.corroboration_rate))} level={scoreLevel(scorecard.corroboration_rate)} />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Lead time')}
                      value={value(format.hours(scorecard.lead_time_hours), t_i18n('No object shared with another source in the period.'))}
                      hint={scorecard.first_reporter_share !== null && scorecard.first_reporter_share !== undefined
                        ? t_i18n('Reported first on {share} of the shared objects', { values: { share: format.ratio(scorecard.first_reporter_share, 0) } })
                        : t_i18n('No object shared with another source')}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Accuracy')}
                      value={value(format.ratio(scorecard.accuracy), t_i18n('No object of this source could be checked in the period.'))}
                      level={scoreLevel(scorecard.accuracy)}
                      hint={t_i18n('{count, plural, one {# object checked} other {# objects checked}}', { values: { count: scorecard.evaluated_count ?? 0 } })}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Relevance')}
                      value={isEnterpriseEdition ? value(format.ratio(scorecard.relevance)) : <EEChip />}
                      level={isEnterpriseEdition ? scoreLevel(scorecard.relevance) : 'unknown'}
                      hint={isEnterpriseEdition
                        ? t_i18n('{count, plural, one {# object in a PIR} other {# objects in a PIR}}', { values: { count: scorecard.pir_matched_count ?? 0 } })
                        : t_i18n('Share of the objects matching your PIRs')}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile
                      label={t_i18n('Impact')}
                      value={value(format.score(scorecard.impact_score))}
                      level={scoreLevel(scorecard.impact_score, { scale: 100 })}
                      hint={t_i18n('{count, plural, one {# sighting} other {# sightings}}', { values: { count: scorecard.sightings_count ?? 0 } })}
                    />
                  </Grid>
                  <Grid size={{ xs: 6, md: 3 }}>
                    <MetricTile label={t_i18n('Noise')} value={value(format.ratio(scorecard.noise))} level={scoreLevel(scorecard.noise, { higherIsBetter: false })} />
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
                    [t_i18n('Declared cost'), source.cost
                      ? t_i18n(DECLARED_AMOUNT_LABELS[source.cost.period] ?? DECLARED_AMOUNT_LABELS.month, {
                          values: { amount: format.cost(source.cost.amount, source.cost.currency) },
                        })
                      : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Box component="span" tabIndex={0} sx={{ color: 'text.disabled' }}>{t_i18n('Not set')}</Box>
                            </TooltipTrigger>
                            <TooltipContent>{t_i18n('No cost declared for this source. Set it with the cost editor above.')}</TooltipContent>
                          </Tooltip>
                        )],
                    [t_i18n('Actionable objects'), value(format.count(scorecard.actionable_count))],
                    [t_i18n('Cost per actionable object'), value(format.cost(scorecard.cost_per_actionable_object, currency), t_i18n('Needs a declared cost and at least one actionable object.'))],
                    [t_i18n('Last assertion'), scorecard.last_asserted_at ? <RelativeTime date={scorecard.last_asserted_at} /> : t_i18n('Not recorded')],
                    [t_i18n('Time since last assertion'), value(format.hours(scorecard.freshness_hours))],
                    [t_i18n('Median publication latency'), value(format.hours(scorecard.median_latency_hours))],
                    [t_i18n('Community uniqueness'), value(format.ratio(scorecard.community_uniqueness), t_i18n('Available when Threat Pulse data is joined to the indicators of this source.'))],
                  ]}
                  />
                </Card>
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Volume')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Entities'), value(format.count(scorecard.volume_entities))],
                    [t_i18n('Relationships'), value(format.count(scorecard.volume_relationships))],
                    [t_i18n('Indicators'), value(format.count(scorecard.volume_indicators))],
                    [t_i18n('Observables'), value(format.count(scorecard.volume_observables))],
                    [t_i18n('Last 24 hours'), value(format.count(scorecard.volume_last_day))],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Accuracy')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Revoked'), value(format.count(scorecard.revoked_count))],
                    [t_i18n('Negative sightings'), value(format.count(scorecard.negative_sightings_count))],
                    [t_i18n('False positives'), value(format.count(scorecard.false_positive_count))],
                    [t_i18n('Decay exclusions'), value(format.count(scorecard.decay_excluded_count))],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Impact')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Sightings'), value(format.count(scorecard.sightings_count))],
                    [t_i18n('Security platform sightings'), value(format.count(scorecard.security_platform_sightings_count))],
                    [t_i18n('Hunt true positives'), value(format.count(scorecard.hunt_true_positives_count))],
                    [t_i18n('Incidents referencing'), value(format.count(scorecard.incidents_count))],
                  ]}
                  />
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 3 }}>
                <Card title={t_i18n('Noise')} fullHeight>
                  <BreakdownList rows={[
                    [t_i18n('Never referenced'), value(format.count(scorecard.unreferenced_count))],
                    [t_i18n('Never sighted'), value(format.count(scorecard.unsighted_count))],
                    [t_i18n('Expired'), value(format.count(scorecard.expired_count))],
                    [t_i18n('Noisy objects'), value(format.count(scorecard.noise_count))],
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
                          : t_i18n('Restricted source')}
                      </Box>
                      <Box sx={{ flex: 1 }}><ValueScoreBar value={share.share * 100} /></Box>
                      <Typography variant="caption" sx={{ minWidth: 140, textAlign: 'right' }}>
                        {t_i18n('{count, plural, one {# shared object} other {# shared objects}}', { values: { count: share.shared_count } })}
                      </Typography>
                    </Stack>
                  ))}
                </Stack>
              )}
            </Card>
          </>
        )}
        <Box id={RECOMMENDATIONS_ANCHOR} sx={{ scrollMarginTop: 80 }}>
          <Card title={t_i18n('Recommendations')}>
            {!isEnterpriseEdition && <EnterpriseEdition feature={t_i18n('Source Intelligence recommendations')} />}
            {isEnterpriseEdition && <SourceRecommendationsSection sourceId={source.id} />}
          </Card>
        </Box>
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
    return <SourceDetailSkeleton />;
  }
  return (
    <Suspense fallback={<SourceDetailSkeleton />}>
      <SourceDetailComponent queryRef={queryRef} period={period} onPeriodChange={setPeriod} />
    </Suspense>
  );
};

export default SourceDetail;
