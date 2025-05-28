import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Chart from '@components/common/charts/Chart';
import { Props as ApexProps } from 'react-apexcharts';
import { useTheme } from '@mui/material/styles';
import { PirOverviewThreatMapFragment$key } from './__generated__/PirOverviewThreatMapFragment.graphql';
import { colors } from '../../../utils/Charts';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { simpleNumberFormat } from '../../../utils/Number';
import { monthsAgo } from '../../../utils/Time';

const threatMapFragment = graphql`
  fragment PirOverviewThreatMapFragment on Query {
    stixRefRelationships(
      first: 50
      orderBy: pir_score
      orderMode: desc
      toId: $toId
      relationship_type: ["in-pir"]
    ) {
      edges {
        node {
          pir_score
          updated_at
            from {
              ...on StixCoreObject {
                representative {
                  main
                }
              }
            }
        }
      }
    }
  }
`;

interface PirOverviewThreatMapProps {
  data: PirOverviewThreatMapFragment$key
}

const PirOverviewThreatMap = ({ data }: PirOverviewThreatMapProps) => {
  const theme = useTheme<Theme>();
  const { fsd } = useFormatter();

  const { stixRefRelationships } = useFragment(threatMapFragment, data);
  const chartSeries = (stixRefRelationships?.edges ?? []).map((e) => ({
    name: e?.node.from?.representative?.main ?? '',
    data: [{ y: e?.node.pir_score ?? 0, x: new Date(e?.node.updated_at) }],
  }));

  const before = monthsAgo(1);
  console.log(before);

  const options: ApexProps['options'] = {
    chart: {
      type: 'scatter',
      background: theme.palette.background.paper,
      toolbar: {
        show: false,
      },
      foreColor: theme.palette.text?.secondary,
      width: '100%',
      height: '100%',
    },
    theme: {
      mode: theme.palette.mode,
    },
    dataLabels: {
      enabled: false,
    },
    colors: [
      theme.palette.primary.main,
      ...colors(theme.palette.mode === 'dark' ? 400 : 600),
    ],
    states: {
      hover: {
        filter: {
          type: 'lighten',
        },
      },
    },
    grid: {
      borderColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .1)'
          : 'rgba(0, 0, 0, .1)',
      strokeDashArray: 3,
    },
    legend: {
      show: false,
    },
    stroke: {
      curve: 'smooth',
      width: 2,
    },
    tooltip: {
      theme: theme.palette.mode,
    },
    xaxis: {
      type: 'datetime',
      tickAmount: 'dataPoints',
      tickPlacement: 'on',
      min: new Date(monthsAgo(1)).getTime(),
      max: new Date().getTime(),
      labels: {
        show: true,
        formatter: (value) => fsd(value),
      },
      axisBorder: {
        show: false,
      },
    },
    yaxis: {
      min: 0,
      max: 100,
      labels: { show: false },
    },
  };

  return (
    <Chart
      isReadOnly
      type="scatter"
      series={chartSeries}
      options={options}
    />
  );
};

export default PirOverviewThreatMap;
