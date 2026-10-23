import React from 'react';
import type { Theme } from '../../../../../components/Theme';
import type { ScaleConfig } from './scale';
import { styled, useTheme } from '@mui/material/styles';

const Rail = styled('span')({
  height: '5px',
  width: '100%',
  display: 'block',
});

const Bar = styled('div')({
  display: 'flex',
  width: '100%',
  padding: '20px 0 20px 0',
});

const TickContainer = styled('div')({
  display: 'flex',
  flexDirection: 'column',
  flex: 1, // same size for all ticks
});

const TickLabel = styled('div')({
  textAlign: 'center',
  fontSize: 12,
  padding: '10px 4px',
});

const TickValue = styled('div')({
  textAlign: 'left',
});

const ScaleBar = ({ scale }: { scale: ScaleConfig }) => {
  const theme = useTheme<Theme>();
  const ticks = [scale.min, ...scale.ticks];

  return (
    <Bar>
      {ticks.map((tick, index) => (
        <TickContainer key={index}>
          <TickValue>
            <span style={{ color: `${index === 0 ? theme.palette.designSystem.tertiary.grey[400] : tick.color}` }}>
              {tick.value}
            </span>
            {index === scale.ticks.length && (
              <span style={{ color: `${tick.color}`, float: 'right' }}>{scale.max.value}</span>
            )}
          </TickValue>
          <div>
            <Rail
              style={{ backgroundColor: `${tick.color ? tick.color : theme.palette.designSystem.tertiary.blue[500]}` }}
            >
            </Rail>
          </div>
          <TickLabel>
            <span>{tick.label}</span>
          </TickLabel>
        </TickContainer>
      ))}
    </Bar>
  );
};

export default ScaleBar;
