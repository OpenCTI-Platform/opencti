import React from 'react';
import Tooltip from '@mui/material/Tooltip';
import { Box } from '@mui/material';

// Marker shapes used to differentiate entities on top of colour, so the encoding
// never relies on colour alone (WCAG 1.4.1 - Use of Color).
export type MarkerShape
  = | 'circle'
    | 'square'
    | 'triangle'
    | 'diamond'
    | 'star'
    | 'plus'
    | 'hexagon'
    | 'pentagon';
export const MARKER_SHAPES: MarkerShape[] = [
  'circle',
  'square',
  'triangle',
  'diamond',
  'star',
  'plus',
  'hexagon',
  'pentagon',
];

// SVG geometry for each shape within a 16x16 viewbox.
const renderShape = (shape: MarkerShape, color: string) => {
  const common = { fill: color, stroke: 'rgba(0, 0, 0, 0.35)', strokeWidth: 0.75 };
  switch (shape) {
    case 'square':
      return <rect x={2.5} y={2.5} width={11} height={11} {...common} />;
    case 'triangle':
      return <polygon points="8,2 14,14 2,14" {...common} />;
    case 'diamond':
      return <polygon points="8,1.5 14.5,8 8,14.5 1.5,8" {...common} />;
    case 'star':
      return (
        <polygon
          points="8,1.5 9.9,6.1 14.8,6.1 10.9,9.2 12.4,14 8,11 3.6,14 5.1,9.2 1.2,6.1 6.1,6.1"
          {...common}
        />
      );
    case 'plus':
      return <polygon points="6,2 10,2 10,6 14,6 14,10 10,10 10,14 6,14 6,10 2,10 2,6 6,6" {...common} />;
    case 'hexagon':
      return <polygon points="4.5,2.5 11.5,2.5 15,8 11.5,13.5 4.5,13.5 1,8" {...common} />;
    case 'pentagon':
      return <polygon points="8,1.5 14.5,6.3 12,14 4,14 1.5,6.3" {...common} />;
    case 'circle':
    default:
      return <circle cx={8} cy={8} r={6} {...common} />;
  }
};

interface MatrixEntityMarkerProps {
  shape: MarkerShape;
  color: string;
  label: string;
  size?: number;
}

// A single colour + shape marker with an accessible text alternative.
const MatrixEntityMarker = ({ shape, color, label, size = 12 }: MatrixEntityMarkerProps) => {
  return (
    <Tooltip title={label}>
      <Box
        component="svg"
        viewBox="0 0 16 16"
        role="img"
        aria-label={label}
        sx={{ width: size, height: size, flex: '0 0 auto', display: 'block' }}
      >
        {renderShape(shape, color)}
      </Box>
    </Tooltip>
  );
};

export default MatrixEntityMarker;
