import { ResponsiveContainer, Scatter, ScatterChart, YAxis, ZAxis, Tooltip, TooltipProps } from 'recharts';
import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/material/styles';
import { computeTimeRangeValuesDomain, GraphTimeRange } from '../utils/graphTimeRange';
import type { Theme } from '../../../components/Theme';
import { useGraphContext } from '../GraphContext';
import { dateFormat } from '../../Time';
import TimeRange from '../../../components/range_slider/RangeSlider';
import { useFormatter } from '../../../components/i18n';
import useGraphInteractions from '../utils/useGraphInteractions';

const TimeRangeTooltip: TooltipProps<number, string>['content'] = ({
  active,
  payload,
}) => {
  const { fldt } = useFormatter();
  const theme = useTheme<Theme>();

  if (!active || !payload || !payload[0]) return null;

  const { time, value }: GraphTimeRange['values'][0] = payload[0].payload;
  const date = fldt(time * 1000);

  const style: CSSProperties = {
    transform: 'translate(-50%, -40px)',
    background: theme.palette.background.paper,
    padding: theme.spacing(1),
    paddingLeft: theme.spacing(2),
    paddingRight: theme.spacing(2),
    borderRadius: theme.spacing(0.5),
    display: 'flex',
    gap: theme.spacing(1),
  };

  return (
    <div style={style}>
      <span>{date}</span>
      <span>-</span>
      <span>{value}</span>
    </div>
  );
};

const GraphToolbarTimeRange = () => {
  const theme = useTheme<Theme>();
  const { setSelectedTimeRange } = useGraphInteractions();
  const { timeRange, graphState } = useGraphContext();
  const { selectedTimeRangeInterval } = graphState;

  return (
    <div style={{
      position: 'relative',
      height: 80,
      marginLeft: theme.spacing(2),
      marginRight: theme.spacing(2),
    }}
    >
      <ResponsiveContainer width="100%" height={60}>
        <ScatterChart
          height={60}
          margin={{ top: 32 }}
        >
          <YAxis
            type="number"
            dataKey="index"
            name="scatter"
            width={0}
            tick={false}
            tickLine={false}
            axisLine={false}
          />
          <ZAxis
            type="number"
            dataKey="value"
            range={[15, 200]}
            domain={computeTimeRangeValuesDomain(timeRange.values)}
          />
          <Tooltip content={TimeRangeTooltip} />
          <Scatter
            data={timeRange.values}
            fill={theme.palette.primary.main}
          />
        </ScatterChart>
      </ResponsiveContainer>

      <div style={{
        position: 'absolute',
        top: 30,
        left: 0,
        right: 0,
        bottom: 0,
      }}
      >
        <TimeRange
          ticksNumber={15}
          selectedInterval={selectedTimeRangeInterval ?? timeRange.interval}
          timelineInterval={timeRange.interval}
          onUpdateCallback={() => null}
          onChangeCallback={setSelectedTimeRange}
          formatTick={dateFormat}
          containerClassName="timerange"
        />
      </div>
    </div>
  );
};

export default GraphToolbarTimeRange;
