import React, { FunctionComponent } from 'react';
import * as R from 'ramda';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import Chart from '../../common/charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import { radarChartOptions } from '../../../../utils/Charts';
import { generateGreenToRedColors } from '../../../../utils/Colors';
import { StixCoreObjectOpinionsRadarDistributionQuery } from './__generated__/StixCoreObjectOpinionsRadarDistributionQuery.graphql';
import { simpleNumberFormat } from '../../../../utils/Number';

export const stixCoreObjectOpinionsRadarDistributionQuery = graphql`
  query StixCoreObjectOpinionsRadarDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    opinionsDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
        ... on Malware {
          name
        }
      }
    }
  }
`;

interface StixCoreObjectOpinionsRadarProps {
  queryRef: PreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>
  height: number
  opinionOptions: { label: string, value: number }[]
}

const StixCoreObjectOpinionsRadar: FunctionComponent<
StixCoreObjectOpinionsRadarProps
> = ({
  queryRef,
  height,
  opinionOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { opinionsDistribution } = usePreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>(
    stixCoreObjectOpinionsRadarDistributionQuery,
    queryRef,
  );

  const distributionData = R.indexBy(
    R.prop('label'),
    (opinionsDistribution || []).map((n) => ({
      ...n,
      label: n?.label.toLowerCase(),
    })),
  );
  const chartData = [
    {
      name: t_i18n('Opinions'),
      data: opinionOptions.map((m) => distributionData[m.label]?.value || 0),
    },
  ];
  const labels = opinionOptions.map((m) => m.label);
  const colors = generateGreenToRedColors(opinionOptions.length);

  return (
    <Chart
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      // Need to migrate Chart Charts.js file to TSX
      options={radarChartOptions(theme, labels, simpleNumberFormat, colors, true, true, 'transparent')}
      series={chartData}
      type="radar"
      width="100%"
      height={height}
    />
  );
};

export default StixCoreObjectOpinionsRadar;
