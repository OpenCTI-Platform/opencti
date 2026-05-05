import { Handle, NodeProps, Position, useReactFlow } from 'reactflow';
import { useFormatter } from '../../../../../../components/i18n';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { NODE_SIZE } from '../utils';
import { snakeCaseToSentenceCase } from '../../../../../../utils/String';
import { useMemo } from 'react';

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

  // Detect if this is a backward transition (going back to an ancestor status)
  const isBackwardTransition = useMemo(() => {
    const outgoingEdge = edges.find((edge) => edge.source === id);
    const incomingEdge = edges.find((edge) => edge.target === id);

    if (!outgoingEdge || !incomingEdge) return false;

    const sourceStatusId = incomingEdge.source;
    const targetStatusId = outgoingEdge.target;

    // Check if target is an ancestor of source by traversing parent relationships
    const isAncestor = (ancestorId: string, descendantId: string): boolean => {
      let currentId = descendantId;
      const visited = new Set<string>();

      while (currentId && !visited.has(currentId)) {
        if (currentId === ancestorId) return true;
        visited.add(currentId);

        // Find parent by looking for incoming edges
        const parentEdge = edges.find((e) => e.target === currentId && e.source !== id);
        if (!parentEdge) break;
        currentId = parentEdge.source;
      }
      return false;
    };

    return isAncestor(targetStatusId, sourceStatusId);
  }, [edges, id]);

  const conditionAndActions = useMemo(() => {
    const filterCount = data.conditions?.filters?.filters?.length ?? 0;
    const filterGroupCount = data.conditions?.filters?.filterGroups?.length ?? 0;
    const totalConditions = filterCount + filterGroupCount;
    const hasConditions = totalConditions > 0;
    const hasActions = data.actions?.length > 0;
    return (
      <>
        {hasConditions && `${totalConditions} ${t_i18n('conditions')}`}
        {hasConditions && hasActions && ' | '}
        {hasActions && `${data.actions?.length} ${t_i18n('actions')}`}
      </>
    );
  }, [data.conditions, data.actions]);

  const hexagonPath = generatePath([
    [0, innerHeight / 2],
    [skew, 0],
    [innerWidth - skew, 0],
    [innerWidth, innerHeight / 2],
    [innerWidth - skew, innerHeight],
    [skew, innerHeight],
  ]);

  const targetPosition = isBackwardTransition ? Position.Bottom : Position.Top;
  const sourcePosition = isBackwardTransition ? Position.Top : Position.Bottom;

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
      <Handle
        type="target"
        position={targetPosition}
        style={{ visibility: hasIncomingEdge ? 'hidden' : 'visible', [isBackwardTransition ? 'bottom' : 'top']: -2 }}
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
              {snakeCaseToSentenceCase(data.event.replace(/_/g, ' '))}
            </div>
            <ul style={{ margin: 0, padding: 0, listStyleType: 'none' }}>
              <li>
                {conditionAndActions}
              </li>
              {data.comment && data.comment !== 'disable' && (
                <li>
                  {data.comment === 'required' ? t_i18n('comment required') : t_i18n('comment allowed')}
                </li>
              )}
            </ul>
          </div>
        </foreignObject>
      </svg>
      <Handle
        type="source"
        position={sourcePosition}
        style={{ visibility: hasOutgoingEdge ? 'hidden' : 'visible', [isBackwardTransition ? 'top' : 'bottom']: -2 }}
      />
    </div>
  );
};

export default TransitionNode;
