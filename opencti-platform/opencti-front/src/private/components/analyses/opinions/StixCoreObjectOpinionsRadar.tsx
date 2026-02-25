import React, { FunctionComponent, useEffect } from 'react';
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
  queryRef: PreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>;
  height: number;
  opinionOptions: { label: string; value: number }[];
  handleOpen: () => void;
  onHasDataChange?: (hasData: boolean) => void;
}

const StixCoreObjectOpinionsRadar: FunctionComponent<StixCoreObjectOpinionsRadarProps> = ({ queryRef, opinionOptions, height, handleOpen, onHasDataChange }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { opinionsDistribution } = usePreloadedQuery<StixCoreObjectOpinionsRadarDistributionQuery>(stixCoreObjectOpinionsRadarDistributionQuery, queryRef);
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
  const hasData = !!opinionsDistribution && opinionsDistribution.length > 0;

  useEffect(() => {
    onHasDataChange?.(hasData);
  }, [hasData]);

  const handleRadarOpen = () => {
    if (hasData) handleOpen();
  };

  if (opinionOptions.length === 0) {
    return (
      <div style={{ pointerEvents: 'none', cursor: 'auto' }}>
        <Chart
          options={{
            noData: {
              text: t_i18n('No data available.'),
              align: 'center',
              verticalAlign: 'middle',
              style: { color: '#888', fontSize: '14px' },
            },
          }}
          series={[]}
          type="radar"
          width="100%"
          height={height}
        />
      </div>
    );
  }

  return (
    <Chart
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      // Need to migrate Chart Charts.js file to TSX
      options={radarChartOptions(theme, labels, simpleNumberFormat, colors, true, 'transparent', (height / 2) - 20, handleRadarOpen)}
      series={chartData}
      type="radar"
      width="100%"
      height="100%"
    />
  );
};

export default StixCoreObjectOpinionsRadar;
