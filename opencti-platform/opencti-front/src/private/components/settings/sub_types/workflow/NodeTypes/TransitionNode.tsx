import { Handle, NodeProps, Position, useReactFlow } from 'reactflow';
import { useFormatter } from '../../../../../../components/i18n';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { NODE_SIZE } from '../utils';

const generatePath = (points: number[][]) => {
  const path = points.map(([x, y]) => `${x},${y}`).join(' L');
  return `M${path} Z`;
};

const TransitionNode = ({ data, id }: NodeProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { getEdges } = useReactFlow();
  const skew = NODE_SIZE.height * 0.2;
  const strokeWidth = 1;

  const innerWidth = NODE_SIZE.width - 2 * strokeWidth;
  const innerHeight = NODE_SIZE.height - 2 * strokeWidth;

  const edges = getEdges();
  const hasIncomingEdge = edges.some((edge) => edge.target === id);
  const hasOutgoingEdge = edges.some((edge) => edge.source === id);

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
      <Handle
        type="target"
        position={Position.Top}
        style={{ visibility: hasIncomingEdge ? 'hidden' : 'visible', top: -2 }}
      />
      <svg width={NODE_SIZE.width} height={NODE_SIZE.height}>
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
        <foreignObject x="0" y="0" width={NODE_SIZE.width} height={NODE_SIZE.height}>
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
              <li>
                {!!data.conditions?.length && `${data.conditions?.length} ${t_i18n('conditions')}`}
                {!!data.conditions?.length && !!data.actions?.length ? ' | ' : ' '}
                {!!data.actions?.length && `${data.actions?.length} ${t_i18n('actions')}`}
              </li>
            </ul>
          </div>
        </foreignObject>
      </svg>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ visibility: hasOutgoingEdge ? 'hidden' : 'visible', bottom: -2 }}
      />
    </div>
  );
};

export default TransitionNode;
