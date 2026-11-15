import React, { useState } from 'react';
import { BaseEdge, EdgeLabelRenderer, EdgeProps, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import { AddOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from '../../../../../../components/Theme';
import { PLAYBOOK_ARROW_ID } from '../nodes/playbookNodeGeometry';
import { playbookEdgePath } from './playbookEdgePath';

// A link between two steps, on whole pixels: one straight segment when its ends are aligned, else
// an orthogonal step with rounded corners, and an arrowhead. The port it leaves from is named on
// the pill of the source card, so nothing is written over the link. The "insert a step here"
// button shows on hover of the link, at its middle.
export default function CustomEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  markerEnd,
  data,
}: EdgeProps) {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { getEdge } = useReactFlow();
  const [hover, setHover] = useState(false);
  const { path: edgePath, labelX: centerX, labelY: centerY } = playbookEdgePath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
  });
  const stroke = hover ? theme.palette.primary.main : theme.palette.text?.secondary;
  return (
    <g onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd ?? `url(#${PLAYBOOK_ARROW_ID})`}
        interactionWidth={24}
        style={{ stroke, strokeWidth: hover ? 2 : 1.5, fill: 'none', shapeRendering: 'geometricPrecision' }}
      />
      <EdgeLabelRenderer>
        <div
          className="nodrag nopan"
          data-testid={`playbook-insert-${id}`}
          onMouseEnter={() => setHover(true)}
          onMouseLeave={() => setHover(false)}
          onFocus={() => setHover(true)}
          onBlur={() => setHover(false)}
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${centerX}px, ${centerY}px)`,
            pointerEvents: 'all',
            borderRadius: '50%',
            opacity: hover ? 1 : 0,
            transition: 'opacity 120ms',
            backgroundColor: theme.palette.background.paper,
            border: `1px solid ${theme.palette.primary.main}`,
          }}
        >
          <IconButton
            aria-label={t_i18n('Insert a component on this link')}
            tooltip={t_i18n('Insert a component on this link')}
            size="small"
            onClick={() => data.openConfig(getEdge(id))}
          >
            <AddOutlined style={{ fontSize: 14 }} />
          </IconButton>
        </div>
      </EdgeLabelRenderer>
    </g>
  );
}
