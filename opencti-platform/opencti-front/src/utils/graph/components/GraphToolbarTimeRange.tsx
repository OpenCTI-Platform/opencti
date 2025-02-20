import { ResponsiveContainer, Scatter, ScatterChart, YAxis, ZAxis } from 'recharts';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import { computeTimeRangeValuesDomain } from '../utils/graphTimeRange';
import type { Theme } from '../../../components/Theme';
import { useGraphContext } from '../GraphContext';
import { dateFormat } from '../../Time';
import TimeRange from '../../../components/range_slider/RangeSlider';

const GraphToolbarTimeRange = () => {
  const theme = useTheme<Theme>();
  const { timeRange } = useGraphContext();

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
          selectedInterval={timeRange.interval} // TODO change
          timelineInterval={timeRange.interval}
          onUpdateCallback={() => null}
          onChangeCallback={console.log}
          formatTick={dateFormat}
          containerClassName="timerange"
        />
      </div>
    </div>
  );
};

export default GraphToolbarTimeRange;
