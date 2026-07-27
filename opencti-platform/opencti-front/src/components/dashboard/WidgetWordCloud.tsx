import React, { useMemo, useRef } from 'react';
import { useTheme } from '@mui/styles';
import ReactWordcloud, { Props } from 'react-wordcloud';
import type { Theme } from '../Theme';
import { colors } from '../../utils/Charts';
import useDistributionGraphData from '../../utils/hooks/useDistributionGraphData';
import useResizeObserver from '../../utils/hooks/useResizeObserver';
import WidgetNoData from './WidgetNoData';

interface WidgetWordCloudProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: readonly any[];
  groupBy: string;
}

// Imported widgets can mount before the layout settles; avoid rendering on tiny/unstable boxes.
const MIN_RENDER_SIZE = 10;

const WidgetWordCloud = ({ data, groupBy }: WidgetWordCloudProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetWordCloudOption } = useDistributionGraphData();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { width, height } = useResizeObserver(containerRef);

  const wordCloudData = useMemo(
    () => buildWidgetWordCloudOption(data, groupBy),
    [data, groupBy],
  );

  const sanitizedWords = useMemo(
    // Log scale requires strictly positive finite values; 0/NaN can crash d3-wordcloud internals.
    () => wordCloudData.filter((w) => Number.isFinite(w.value) && w.value > 0),
    [wordCloudData],
  );

  const options: Props['options'] = useMemo(() => {
    const wordCloudColors = colors(theme.palette.mode === 'dark' ? 400 : 600);
    return {
      colors: wordCloudColors,
      fontFamily: 'IBM Plex Sans',
      spiral: 'rectangular',
      rotations: 1,
      rotationAngles: [0, 0],
      deterministic: true,
      fontSizes: [20, 50],
      scale: 'log',
    };
  }, [theme]);

  const isContainerReady = width > MIN_RENDER_SIZE && height > MIN_RENDER_SIZE;
  const hasRenderableWords = sanitizedWords.length > 0;
  // Imported widgets can briefly mount with zero-size container or non-positive values.
  // With d3 log scale, those transient inputs can produce invalid domains and crash wordcloud layout.
  const shouldRenderWordCloud = isContainerReady && hasRenderableWords;
  const shouldRenderEmptyState = isContainerReady && !hasRenderableWords;

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
      {shouldRenderWordCloud && (
        <ReactWordcloud
          words={sanitizedWords}
          minSize={[1, 1]}
          options={options}
        />
      )}
      {shouldRenderEmptyState && (
        <WidgetNoData />
      )}
    </div>
  );
};

export default WidgetWordCloud;
