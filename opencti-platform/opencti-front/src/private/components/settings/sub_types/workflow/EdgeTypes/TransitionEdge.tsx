import { useContext, useState } from 'react';
import { EdgeProps, getSmoothStepPath, type XYPosition } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import { Icon, IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@filigran/design-system';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import { getRoutePath } from '../layout/route';
import { WorkflowEdgeActionsContext } from './WorkflowEdgeActionsContext';
import { hoverFade, useEdgeHighlight } from '../hoverHighlight';

const BADGE_SIZE = 24;

const TransitionEdge = ({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  data,
  selected,
}: EdgeProps<{ route?: XYPosition[] }>) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { insertStatus, deleteConnection } = useContext(WorkflowEdgeActionsContext);
  const [isHovered, setIsHovered] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { lit, dimmed } = useEdgeHighlight(id);
  const strokeWidth = isHovered || lit ? 1.5 : 1;
  // useWorkflowLayout routes every edge; smoothstep covers the frame before the first layout.
  const route = data?.route;
  const [edgePath, edgeCenterX, edgeCenterY] = route && route.length >= 2
    ? getRoutePath(route)
    : getSmoothStepPath({
        sourceX,
        sourceY,
        sourcePosition,
        targetX,
        targetY,
        targetPosition,
        borderRadius: 10,
        offset: 10,
      });

  return (
    <g
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      // Fades while a hovered node's neighbourhood leaves this edge out.
      style={hoverFade(dimmed)}
    >
      <path
        id={id}
        style={{
          fill: 'none',
          stroke: theme.palette.primary.main,
          transition: 'stroke-width 0.2s',
          strokeWidth,
        }}
        d={edgePath}
        markerEnd={markerEnd}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={20}
        style={{ cursor: 'pointer' }}
        onClick={() => setMenuOpen(true)}
      />

      {/* The edge menu: insert a status here, or delete this connection. A selected edge keeps
          its badge, so a keyboard user (Tab to the edge, Enter to select it) can reach it. */}
      {(isHovered || menuOpen || selected) && (
        <foreignObject
          x={edgeCenterX - BADGE_SIZE / 2}
          y={edgeCenterY - BADGE_SIZE / 2}
          width={BADGE_SIZE}
          height={BADGE_SIZE}
          style={{ overflow: 'visible' }}
        >
          <Menu open={menuOpen} onOpenChange={setMenuOpen}>
            <MenuTrigger asChild>
              <IconButton
                size="sm"
                priority="secondary"
                aria-label={t_i18n('Edge actions')}
                icon={<Icon name="ellipsis-vertical" size={16} />}
                // Outlined badge: the canvas colour behind it hides the edge line; the smallest IconButton is 24px.
                style={{
                  width: BADGE_SIZE,
                  height: BADGE_SIZE,
                  minWidth: BADGE_SIZE,
                  backgroundColor: theme.palette.background.default,
                  borderColor: theme.palette.primary.main,
                  transition: 'border-width 0.2s',
                  borderWidth: strokeWidth,
                }}
              />
            </MenuTrigger>
            <MenuContent
              align="start"
              style={{ minWidth: 'var(--radix-dropdown-menu-trigger-width)', maxWidth: 'calc(100vw - 32px)' }}
            >
              <MenuItem startIcon={<Icon name="circle-plus" size={16} />} onSelect={() => insertStatus({ id, source, target })}>
                {t_i18n('Insert status here')}
              </MenuItem>
              <MenuSeparator />
              <MenuItem
                startIcon={<Icon name="trash-2" size={16} className="text-icon-error" />}
                // FDS-WORKAROUND #64: MenuItem has no destructive tone — see fds-migration/LIBRARY-FEEDBACK.md #64
                style={{ color: theme.palette.error.main }}
                onSelect={() => deleteConnection(id)}
              >
                {t_i18n('Delete connection')}
              </MenuItem>
            </MenuContent>
          </Menu>
        </foreignObject>
      )}
    </g>
  );
};

export default TransitionEdge;
