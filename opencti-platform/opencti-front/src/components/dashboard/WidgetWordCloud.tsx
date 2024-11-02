import React from 'react';
import { useTheme } from '@mui/styles';
import ReactWordcloud from 'react-wordcloud';
// eslint-disable-next-line import/no-extraneous-dependencies
import 'tippy.js/dist/tippy.css';
// eslint-disable-next-line import/no-extraneous-dependencies
import 'tippy.js/animations/scale.css';
import type { Theme } from '../Theme';
import { colors } from '../../utils/Charts';
import useDistributionGraphData from '../../utils/hooks/useDistributionGraphData';

interface WidgetWordCloudProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  groupBy: string
}

const WidgetWordCloud = ({ data, groupBy }: WidgetWordCloudProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetWordCloudOption } = useDistributionGraphData();
  const wordCloudColors = colors(theme.palette.mode === 'dark' ? 400 : 600);
  const wordCloudData = buildWidgetWordCloudOption(data, groupBy);
  return (
    <ReactWordcloud
      words={wordCloudData}
      options={{
        colors: wordCloudColors,
        fontFamily: 'IBM Plex Sans',
        spiral: 'rectangular',
        rotations: 1,
        rotationAngles: [0, 0],
        deterministic: true,
        fontSizes: [20, 50],
        scale: 'log',
      }}
    />
  );
};

export default WidgetWordCloud;
