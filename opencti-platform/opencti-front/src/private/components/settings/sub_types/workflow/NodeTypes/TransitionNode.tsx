import React from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { generatePath } from '../Workflow';

const width = 160;
const height = 50;

const TransitionNode = ({ data }: NodeProps) => {
  const theme = useTheme<Theme>();
  const skew = height * 0.2;
  const strokeWidth = 1;

  const innerWidth = width - 2 * strokeWidth;
  const innerHeight = height - 2 * strokeWidth;

  const hexagonPath = generatePath([
    [0, innerHeight / 2],
    [skew, 0],
    [innerWidth - skew, 0],
    [innerWidth, innerHeight / 2],
    [innerWidth - skew, innerHeight],
    [skew, innerHeight],
  ]);

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
      <Handle type="target" position={Position.Top} style={{ visibility: 'hidden', top: 1 }} />
      <svg width={width} height={height}>
        <g transform={`translate(${strokeWidth}, ${strokeWidth})`}>
          <path
            d={hexagonPath}
            fill={theme.palette.background.paper}
            strokeWidth={strokeWidth}
            stroke={
              theme.palette.mode === 'dark'
                ? 'rgba(255, 255, 255, 0.12)'
                : 'rgba(0, 0, 0, 0.12)'
            }
          />
        </g>
        <foreignObject x="0" y="0" width={width} height={height}>
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
            width: '100%',
            textAlign: 'center',
            fontSize: 9,
            color: theme.palette.primary.main,
            pointerEvents: 'none',
          }}
          >
            <div style={{ fontWeight: 'bold', textTransform: 'uppercase' }}>
              {data.event.replace(/_/g, ' ')}
            </div>
            <ul style={{ margin: 0, padding: 0, listStyleType: 'none' }}>
              <li>{data.conditions?.length || 0} conditions</li>
            </ul>
          </div>
        </foreignObject>
      </svg>
      <Handle type="source" position={Position.Bottom} style={{ visibility: 'hidden', bottom: 1 }} />
    </div>
  );
};

export default TransitionNode;
