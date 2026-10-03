import { Suspense, useMemo } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Box, Grid, Stack, Typography } from '@mui/material';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { useDeploymentStatusLabel, useValidationStatusLabel } from './DisseminationStatusChips';
import { funnelShare, isDeploymentStatus, isValidationStatus } from './disseminationAssuranceUtils';
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
}

const CHART_HEIGHT = 280;

const KpiCard = ({ label, value, caption, testId }: { label: string; value: string; caption?: string; testId: string }) => (
  <Card padding="default" fullHeight>
    <Stack gap={0.5} data-testid={testId}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography variant="h1" component="span" sx={{ fontSize: 28 }}>{value}</Typography>
      {caption && <Typography variant="caption" color="text.secondary">{caption}</Typography>}
    </Stack>
  </Card>
);

const DisseminationAssuranceMetricsContent = ({ platformId, startDate }: DisseminationAssuranceMetricsProps) => {
  const { t_i18n, n } = useFormatter();
  const deploymentLabel = useDeploymentStatusLabel();
  const validationLabel = useValidationStatusLabel();
  const { disseminationAssuranceMetrics: metrics } = useLazyLoadQuery<DisseminationAssuranceMetricsQuery>(
    disseminationAssuranceMetricsQuery,
    { platformId: platformId ?? null, startDate: startDate ?? null, endDate: null },
    { fetchPolicy: 'store-and-network' },
  );
  const funnel = metrics?.funnel;
  const reference = platformId ? (funnel?.disseminated ?? 0) : (funnel?.created ?? 0);

  const funnelStages = useMemo(() => {
    if (!funnel) return [];
    const stages = [
      { label: platformId ? t_i18n('Deployments') : t_i18n('Created'), value: platformId ? funnel.disseminated : funnel.created },
      ...(platformId ? [] : [{ label: t_i18n('Disseminated'), value: funnel.disseminated }]),
      { label: t_i18n('Deployed'), value: funnel.deployed },
      { label: t_i18n('Validated'), value: funnel.validated },
      { label: t_i18n('With hits'), value: funnel.hit },
      { label: t_i18n('Expired but still deployed'), value: funnel.expired_still_deployed },
    ];
    return stages;
  }, [funnel, platformId]);

  if (!metrics || !funnel) {
    return <WidgetNoData />;
  }

  const deploymentDistribution = metrics.deployment_statuses
    .filter((bucket) => isDeploymentStatus(bucket.status))
    .map((bucket) => ({ label: deploymentLabel(bucket.status as never), value: bucket.count }));
  const validationDistribution = metrics.validation_statuses
    .filter((bucket) => isValidationStatus(bucket.status))
    .map((bucket) => ({ label: validationLabel(bucket.status as never), value: bucket.count }));

  return (
    <Stack gap={3} data-testid="dissemination-assurance-metrics">
      <Grid container spacing={3}>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard
            testId="kpi-disseminated"
            label={platformId ? t_i18n('Deployments') : t_i18n('Disseminated')}
            value={n(funnel.disseminated)}
            caption={platformId ? undefined : `${funnelShare(funnel.disseminated, funnel.created)}% ${t_i18n('of created')}`}
          />
        </Grid>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard testId="kpi-deployed" label={t_i18n('Deployed')} value={n(funnel.deployed)} caption={`${funnelShare(funnel.deployed, reference)}%`} />
        </Grid>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard testId="kpi-validated" label={t_i18n('Validated')} value={n(funnel.validated)} caption={`${funnelShare(funnel.validated, reference)}%`} />
        </Grid>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard testId="kpi-hits" label={t_i18n('With hits')} value={n(funnel.hit)} caption={`${funnelShare(funnel.hit, reference)}%`} />
        </Grid>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard testId="kpi-expired" label={t_i18n('Expired but still deployed')} value={n(funnel.expired_still_deployed)} />
        </Grid>
        <Grid item xs={6} md={4} lg={2}>
          <KpiCard
            testId="kpi-proven-share"
            label={t_i18n('Proven share')}
            value={`${metrics.proven_share}%`}
            caption={t_i18n('of live deployments detected or prevented')}
          />
        </Grid>
      </Grid>
      <Grid container spacing={3}>
        <Grid item xs={12} lg={platformId ? 12 : 6}>
          <Card title={t_i18n('Lifecycle funnel')}>
            <Box sx={{ height: CHART_HEIGHT }} data-testid="dissemination-funnel">
              <WidgetHorizontalBars
                series={[{ name: t_i18n('Count'), data: funnelStages.map((stage) => stage.value) }]}
                categories={funnelStages.map((stage) => stage.label)}
                distributed
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
