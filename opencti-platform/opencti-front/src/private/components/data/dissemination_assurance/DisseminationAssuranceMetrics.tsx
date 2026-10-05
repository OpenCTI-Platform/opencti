import { ReactNode, Suspense, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, Grid, Stack, Typography } from '@mui/material';
import { Badge, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import HubFirstUse from '../../common/hub/HubFirstUse';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { useDeploymentStatusLabel, useValidationStatusLabel } from './DisseminationStatusChips';
import {
  buildKpiFilters,
  computeDeploymentKpis,
  DISSEMINATION_ASSURANCE_DOCUMENTATION_URL,
  funnelShare,
  isDeploymentStatus,
  isValidationStatus,
  type KpiId,
  sumStatuses,
} from './disseminationAssuranceUtils';
import type { DisseminationAssuranceMetricsQuery } from './__generated__/DisseminationAssuranceMetricsQuery.graphql';

const disseminationAssuranceMetricsQuery = graphql`
  query DisseminationAssuranceMetricsQuery($platformId: String, $startDate: DateTime, $endDate: DateTime) {
    disseminationAssuranceMetrics(platformId: $platformId, startDate: $startDate, endDate: $endDate) {
      funnel {
        created
        disseminated
        deployed
        validated
        hit
        expired_still_deployed
      }
      deployment_statuses {
        status
        count
      }
      validation_statuses {
        status
        count
      }
      failures_by_platform {
        platform {
          id
          name
        }
        count
      }
      deployments_by_platform {
        platform {
          id
          name
        }
        count
      }
      proven_share
    }
  }
`;

interface DisseminationAssuranceMetricsProps {
  platformId?: string;
  startDate?: string | null;
  /** Renders the deployments under the KPI strip, filtered by the selected counter. */
  renderDeployments?: (kpiFilters: FilterGroup | undefined) => ReactNode;
}

const CHART_HEIGHT = 280;

interface KpiCounterProps {
  id: KpiId;
  label: string;
  value: string;
  caption?: string;
  badge?: string;
  actionable?: boolean;
  selected: boolean;
  onSelect: (id: KpiId) => void;
}

const KpiCounter = ({ id, label, value, caption, badge, actionable, selected, onSelect }: KpiCounterProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Card
      padding="medium"
      onClick={() => onSelect(id)}
      actionAreaProps={{
        'aria-label': selected
          ? t_i18n('{label}: {value}, filter applied', { values: { label, value } })
          : t_i18n('{label}: {value}, filter the deployments', { values: { label, value } }),
        'aria-pressed': selected,
      }}
      sx={{
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'flex-start',
        alignItems: 'stretch',
        ...(selected ? { outline: '2px solid var(--border-input-focus)', outlineOffset: '-2px' } : {}),
      }}
    >
      <Stack gap={0.5} data-testid={`kpi-${id}`}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1}>
          <Typography variant="body2" color="text.secondary">{label}</Typography>
          {badge && <Badge tone="error" content={badge} />}
        </Stack>
        <Typography
          variant="h1"
          component="span"
          sx={actionable ? { color: 'var(--color-feedback-error-primary)' } : undefined}
        >
          {value}
        </Typography>
        {caption && <Typography variant="caption" color="text.secondary" noWrap title={caption}>{caption}</Typography>}
      </Stack>
    </Card>
  );
};

// The stream connectors that report their deployments (product names, never translated).
export const DEPLOYMENT_REPORTING_CONNECTORS = [
  'Microsoft Sentinel Intel',
  'Microsoft Defender Intel',
  'CrowdStrike Endpoint Security',
  'Splunk',
  'Elastic Security Intel',
  'Google SecOps SIEM',
  'SentinelOne Intel',
  'Palo Alto Cortex XDR Intel',
  'Zscaler',
  'Cloudflare Rules List',
];

const FirstUse = () => {
  const { t_i18n } = useFormatter();
  return (
    <HubFirstUse
      action={(
        <Button variant="primary" component={Link} to="/dashboard/integrations/available?type=STREAM">
          {t_i18n('Configure a stream connector')}
        </Button>
      )}
      documentationUrl={DISSEMINATION_ASSURANCE_DOCUMENTATION_URL}
    >
      <Text variant="content-base" data-testid="deployment-reporting-connectors">
        {t_i18n('These stream connectors report their deployments: {connectors}.', {
          values: { connectors: DEPLOYMENT_REPORTING_CONNECTORS.join(', ') },
        })}
      </Text>
      <Text variant="content-base">
        {t_i18n('Their OpenCTI account needs the Connector role, with the Update knowledge and Connectors API usage capabilities.')}
      </Text>
    </HubFirstUse>
  );
};

const DisseminationAssuranceMetricsContent = ({ platformId, startDate, renderDeployments }: DisseminationAssuranceMetricsProps) => {
  const { t_i18n, n } = useFormatter();
  const deploymentLabel = useDeploymentStatusLabel();
  const validationLabel = useValidationStatusLabel();
  const [selectedKpi, setSelectedKpi] = useState<KpiId | null>(null);
  const { disseminationAssuranceMetrics: metrics } = useLazyLoadQuery<DisseminationAssuranceMetricsQuery>(
    disseminationAssuranceMetricsQuery,
    { platformId: platformId ?? null, startDate: startDate ?? null, endDate: null },
    { fetchPolicy: 'store-and-network' },
  );
  const funnel = metrics?.funnel;

  const funnelStages = useMemo(() => {
    if (!funnel) return [];
    return [
      { label: platformId ? t_i18n('Deployments') : t_i18n('Created'), value: platformId ? funnel.disseminated : funnel.created },
      ...(platformId ? [] : [{ label: t_i18n('Disseminated'), value: funnel.disseminated }]),
      { label: t_i18n('Deployed'), value: funnel.deployed },
      { label: t_i18n('Validated'), value: funnel.validated },
      { label: t_i18n('With hits'), value: funnel.hit },
      { label: t_i18n('Expired but still deployed'), value: funnel.expired_still_deployed },
    ];
  }, [funnel, platformId]);

  if (!metrics || !funnel) {
    return <WidgetNoData />;
  }
  const deploymentsCount = sumStatuses(metrics.deployment_statuses);
  if (!platformId && !startDate && deploymentsCount === 0) {
    return <FirstUse />;
  }

  // The counters count the deployments listed under the strip, with the same period and platform.
  const kpis = computeDeploymentKpis(metrics.deployment_statuses, metrics.validation_statuses);
  const shareOfDisseminated = (value: number) => t_i18n('{share}% of the recorded deployments', { values: { share: funnelShare(value, kpis.disseminated) } });
  const counters: Array<Omit<KpiCounterProps, 'selected' | 'onSelect'>> = [
    {
      id: 'disseminated',
      label: t_i18n('Disseminated'),
      value: n(kpis.disseminated),
      caption: t_i18n('Recorded by stream connectors'),
      badge: kpis.failed > 0 ? t_i18n('{count, plural, one {# failed} other {# failed}}', { values: { count: kpis.failed } }) : undefined,
    },
    { id: 'deployed', label: t_i18n('Deployed'), value: n(kpis.deployed), caption: shareOfDisseminated(kpis.deployed) },
    {
      id: 'active',
      label: t_i18n('Active'),
      value: n(kpis.active),
      caption: t_i18n('Confirmed live by the platform'),
    },
    { id: 'validated', label: t_i18n('Validated'), value: n(kpis.validated), caption: shareOfDisseminated(kpis.validated) },
    {
      id: 'missed',
      label: t_i18n('Missed'),
      value: n(kpis.missed),
      caption: t_i18n('Tests the platform missed'),
      actionable: kpis.missed > 0,
    },
  ];
  const selected = counters.find((counter) => counter.id === selectedKpi);

  const deploymentDistribution = metrics.deployment_statuses
    .filter((bucket) => isDeploymentStatus(bucket.status))
    .map((bucket) => ({ label: deploymentLabel(bucket.status as never), value: bucket.count }));
  const validationDistribution = metrics.validation_statuses
    .filter((bucket) => isValidationStatus(bucket.status))
    .map((bucket) => ({ label: validationLabel(bucket.status as never), value: bucket.count }));

  return (
    <Stack gap={3} data-testid="dissemination-assurance-metrics">
      <Box
        role="group"
        aria-label={t_i18n('Key figures')}
        sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)', lg: 'repeat(5, 1fr)' } }}
      >
        {counters.map((counter) => (
          <KpiCounter
            key={counter.id}
            {...counter}
            selected={counter.id === selectedKpi}
            onSelect={(id) => setSelectedKpi((current) => (current === id ? null : id))}
          />
        ))}
      </Box>
      {renderDeployments && (
        <Stack gap={1}>
          {selected && (
            <Stack direction="row" alignItems="center" gap={1} data-testid="kpi-filter-applied">
              <Typography variant="body2" color="text.secondary">
                {t_i18n('Deployments filtered by "{label}"', { values: { label: selected.label } })}
              </Typography>
              <Button variant="tertiary" size="small" onClick={() => setSelectedKpi(null)}>{t_i18n('Clear filters')}</Button>
            </Stack>
          )}
          {renderDeployments(buildKpiFilters(selectedKpi))}
        </Stack>
      )}
      <Grid container spacing={3}>
        <Grid item xs={12} lg={platformId ? 12 : 6}>
          <Card title={t_i18n('Lifecycle funnel')}>
            <Box sx={{ height: CHART_HEIGHT }} data-testid="dissemination-funnel">
              <WidgetHorizontalBars
                series={[{ name: t_i18n('Count'), data: funnelStages.map((stage) => stage.value) }]}
                categories={funnelStages.map((stage) => stage.label)}
              />
            </Box>
          </Card>
        </Grid>
        {!platformId && (
          <Grid item xs={12} lg={6}>
            <Card title={t_i18n('Failures by security platform')}>
              <Box sx={{ height: CHART_HEIGHT }}>
                {metrics.failures_by_platform.length > 0 ? (
                  <WidgetHorizontalBars
                    series={[{ name: t_i18n('Failed'), data: metrics.failures_by_platform.map((item) => item.count) }]}
                    categories={metrics.failures_by_platform.map((item) => item.platform.name)}
                    redirectionUtils={metrics.failures_by_platform.map((item) => ({ id: item.platform.id, entity_type: 'SecurityPlatform' }))}
                  />
                ) : <WidgetNoData />}
              </Box>
            </Card>
          </Grid>
        )}
        <Grid item xs={12} md={6} lg={platformId ? 6 : 4}>
          <Card title={t_i18n('Deployment statuses')}>
            <Box sx={{ height: CHART_HEIGHT }}>
              {deploymentDistribution.length > 0 ? <WidgetDonut data={deploymentDistribution} groupBy="status" /> : <WidgetNoData />}
            </Box>
          </Card>
        </Grid>
        <Grid item xs={12} md={6} lg={platformId ? 6 : 4}>
          <Card title={t_i18n('Validation statuses')}>
            <Box sx={{ height: CHART_HEIGHT }}>
              {validationDistribution.length > 0 ? <WidgetDonut data={validationDistribution} groupBy="status" /> : <WidgetNoData />}
            </Box>
          </Card>
        </Grid>
        {!platformId && (
          <Grid item xs={12} lg={4}>
            <Card title={t_i18n('Live deployments by security platform')}>
              <Box sx={{ height: CHART_HEIGHT }}>
                {metrics.deployments_by_platform.length > 0 ? (
                  <WidgetHorizontalBars
                    series={[{ name: t_i18n('Live deployments'), data: metrics.deployments_by_platform.map((item) => item.count) }]}
                    categories={metrics.deployments_by_platform.map((item) => item.platform.name)}
                    redirectionUtils={metrics.deployments_by_platform.map((item) => ({ id: item.platform.id, entity_type: 'SecurityPlatform' }))}
                  />
                ) : <WidgetNoData />}
              </Box>
            </Card>
          </Grid>
        )}
      </Grid>
    </Stack>
  );
};

const DisseminationAssuranceMetrics = (props: DisseminationAssuranceMetricsProps) => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <DisseminationAssuranceMetricsContent {...props} />
  </Suspense>
);

export default DisseminationAssuranceMetrics;
