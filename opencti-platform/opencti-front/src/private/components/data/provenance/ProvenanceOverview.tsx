import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/styles';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import CardStatistic from '@common/card/CardStatistic';
import Chart from '@components/common/charts/Chart';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { donutChartOptions, horizontalBarsChartOptions, verticalBarsChartOptions } from '../../../../utils/Charts';
import Security from '../../../../utils/Security';
import { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { FRESHNESS_BUCKET_LABELS, sourceKindLabel } from '../../common/provenance/provenanceUtils';
import ProvenanceBackfillCard from './ProvenanceBackfillCard';
import ProvenanceSettingsCard from './ProvenanceSettingsCard';
import { ProvenanceOverviewQuery } from './__generated__/ProvenanceOverviewQuery.graphql';

const provenanceOverviewQuery = graphql`
  query ProvenanceOverviewQuery {
    provenanceStatistics {
      total
      with_provenance
      single_sourced
      corroborated
      with_conflicts
      stale
    }
    provenanceFreshnessDistribution {
      label
      value
    }
    provenanceSourceKindsDistribution {
      source_kind
      count
    }
    provenanceSingleSourcedByType {
      entity_type
      total
      single_sourced
    }
  }
`;

const MAX_TYPES_DISPLAYED = 10;

const percent = (value: number, total: number) => (total > 0 ? Math.round((value / total) * 100) : 0);

const ProvenanceOverviewContent = () => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const data = useLazyLoadQuery<ProvenanceOverviewQuery>(provenanceOverviewQuery, {}, { fetchPolicy: 'store-and-network' });
  const stats = data.provenanceStatistics;
  const freshness = data.provenanceFreshnessDistribution;
  const sourceKinds = data.provenanceSourceKindsDistribution.filter((entry) => entry.count > 0);
  const byType = data.provenanceSingleSourcedByType.slice(0, MAX_TYPES_DISPLAYED);
  const freshnessCategories = freshness.map((entry) => t_i18n(FRESHNESS_BUCKET_LABELS[entry.label] ?? entry.label));
  const sourceKindLabels = sourceKinds.map((entry) => t_i18n(sourceKindLabel(entry.source_kind)));
  const typeLabels = byType.map((entry) => t_i18n(`entity_${entry.entity_type}`) || entry.entity_type);
  return (
    <Grid container spacing={3} data-testid="provenance-overview">
      <Grid item sx={{ flexBasis: '20%', maxWidth: '20%' }}>
        <CardStatistic label={t_i18n('Knowledge with provenance')} value={`${percent(stats.with_provenance, stats.total)}%`} />
      </Grid>
      <Grid item sx={{ flexBasis: '20%', maxWidth: '20%' }}>
        <CardStatistic label={t_i18n('Single sourced')} value={n(stats.single_sourced)} />
      </Grid>
      <Grid item sx={{ flexBasis: '20%', maxWidth: '20%' }}>
        <CardStatistic label={t_i18n('Corroborated (2+ sources)')} value={n(stats.corroborated)} />
      </Grid>
      <Grid item sx={{ flexBasis: '20%', maxWidth: '20%' }}>
        <CardStatistic label={t_i18n('With source conflicts')} value={n(stats.with_conflicts)} />
      </Grid>
      <Grid item sx={{ flexBasis: '20%', maxWidth: '20%' }}>
        <CardStatistic label={t_i18n('Stale knowledge')} value={n(stats.stale)} />
      </Grid>
      <Grid item xs={6}>
        <Card title={t_i18n('Freshness distribution')}>
          <div data-testid="provenance-freshness-chart">
            <Chart
              options={verticalBarsChartOptions(theme, (value: string) => value, (value: number) => n(value), true) as ApexOptions}
              series={[{ name: t_i18n('Elements'), data: freshness.map((entry, index) => ({ x: freshnessCategories[index], y: entry.value })) }]}
              type="bar"
              width="100%"
              height={280}
            />
          </div>
        </Card>
      </Grid>
      <Grid item xs={6}>
        <Card title={t_i18n('Sources by kind')}>
          <div data-testid="provenance-source-kinds-chart">
            {sourceKinds.length > 0 ? (
              <Chart
                options={donutChartOptions(theme, sourceKindLabels) as ApexOptions}
                series={sourceKinds.map((entry) => entry.count)}
                type="donut"
                width="100%"
                height={280}
              />
            ) : t_i18n('No source asserted any knowledge yet.')}
          </div>
        </Card>
      </Grid>
      <Grid item xs={12}>
        <Card title={t_i18n('Single sourced share by type')}>
          <div data-testid="provenance-single-sourced-chart">
            <Chart
              options={horizontalBarsChartOptions(theme, true, undefined, undefined, false, undefined, undefined, true, false, typeLabels, true) as ApexOptions}
              series={[
                { name: t_i18n('Single sourced'), data: byType.map((entry) => entry.single_sourced) },
                { name: t_i18n('Corroborated'), data: byType.map((entry) => entry.total - entry.single_sourced) },
              ]}
              type="bar"
              width="100%"
              height={Math.max(200, byType.length * 36)}
            />
          </div>
        </Card>
      </Grid>
      <Security needs={[SETTINGS_SETPARAMETERS]}>
        <>
          <Grid item xs={6}>
            <ProvenanceBackfillCard />
          </Grid>
          <Grid item xs={6}>
            <ProvenanceSettingsCard />
          </Grid>
        </>
      </Security>
    </Grid>
  );
};

const ProvenanceOverview = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Provenance | Data'));
  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Provenance') }, { label: t_i18n('Overview'), current: true }]} />
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <ProvenanceOverviewContent />
      </Suspense>
    </>
  );
};

export default ProvenanceOverview;
