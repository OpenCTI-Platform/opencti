import React, { memo, useState } from 'react';
import { Handle, NodeProps, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert, CheckCircleOutlined, ErrorOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../../components/i18n';
import { truncate } from '../../../../../../utils/String';
import type { Theme } from '../../../../../../components/Theme';
import { usePlaybookHandlePositions } from '../../hooks/usePlaybookLayoutMode';
import { categoryAccent, outPorts, PLAYBOOK_CARD, portAnchor } from './playbookNodeGeometry';
import { usePlaybookNodeLastExecution } from '../../hooks/usePlaybookLastExecution';
import { formatStepDuration } from '../../utils/playbookLastExecution';

// The menu opens from the three dots, or at the pointer on a right click.
type MenuAnchor = { element: Element } | { top: number; left: number };

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [anchor, setAnchor] = useState<MenuAnchor | null>(null);
  const [hovered, setHovered] = useState(false);
  const setAnchorEl = (element: Element | null) => setAnchor(element ? { element } : null);
  const lastExecution = usePlaybookNodeLastExecution(id);
  const lastDuration = lastExecution ? formatStepDuration(lastExecution.duration) : null;
  const lastStatusLabel = lastExecution?.status === 'success' ? t_i18n('Success') : t_i18n('Error');
  const { getNode } = useReactFlow();
  const { direction, target, source } = usePlaybookHandlePositions();
  const component = data.component;
  const accent = categoryAccent(theme, component?.category);
  const displayDescription = data.description || component?.description;
  const ports = outPorts(component?.ports);
  const isEntryPoint = Boolean(component?.is_entry_point);
  const isEnd = ports.length === 0;
  const kind = isEntryPoint ? t_i18n('Trigger') : (isEnd ? t_i18n('End of playbook') : t_i18n(component?.category ?? ''));
  const muted = theme.palette.text?.secondary;
  // The card itself opens its configuration (click, Enter or Space): no permanent button for it.
  const openConfiguration = () => data.openConfig(getNode(id));
  return (
    <div
      data-testid={`playbook-node-${id}`}
      role="button"
      tabIndex={0}
      aria-label={`${t_i18n('Update')}: ${t_i18n(data.name)}`}
      onClick={openConfiguration}
      onKeyDown={(event) => {
        if (event.target === event.currentTarget && (event.key === 'Enter' || event.key === ' ')) {
          event.preventDefault();
          openConfiguration();
        }
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onContextMenu={(event) => {
        event.preventDefault();
        setAnchor({ top: event.clientY, left: event.clientX });
      }}
      style={{
        position: 'relative',
        boxSizing: 'border-box',
        width: PLAYBOOK_CARD.width,
        height: PLAYBOOK_CARD.height,
        cursor: 'pointer',
        border: `1px solid ${hovered ? accent : theme.palette.divider}`,
        transition: 'border-color 120ms',
        borderLeft: `4px solid ${accent}`,
        borderRadius: isEntryPoint ? 16 : 6,
        backgroundColor: theme.palette.background.paper,
        boxShadow: theme.shadows?.[1],
        padding: '10px 32px 10px 12px',
        overflow: 'visible',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: accent, display: 'inline-flex' }}>
          <ItemIcon type={component?.icon} variant="inline" color={accent} />
        </span>
        <span style={{ fontSize: 10, letterSpacing: 0.4, textTransform: 'uppercase', color: muted }}>
          {kind}
        </span>
      </div>
      <Tooltip title={t_i18n(data.name)}>
        <div style={{ marginTop: 4, fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {t_i18n(truncate(data.name, 60, false))}
        </div>
      </Tooltip>
      <Tooltip title={t_i18n(displayDescription)}>
        <div style={{
          marginTop: 2,
          fontSize: 11,
          lineHeight: '14px',
          color: muted,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
        >
          {t_i18n(displayDescription)}
        </div>
      </Tooltip>
      <div
        role="presentation"
        style={{ position: 'absolute', top: 4, right: 2 }}
        // The menu and its items act on their own: they never open the configuration as well.
        onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => event.stopPropagation()}
      >
        <IconButton
          aria-label={t_i18n('Open menu')}
          onClick={(event) => setAnchorEl(event.currentTarget)}
          aria-haspopup="true"
          size="small"
        >
          <MoreVert style={{ fontSize: 16 }} />
        </IconButton>
        <Menu
          anchorEl={anchor && 'element' in anchor ? anchor.element : null}
          anchorReference={anchor && 'top' in anchor ? 'anchorPosition' : 'anchorEl'}
          anchorPosition={anchor && 'top' in anchor ? anchor : undefined}
          open={Boolean(anchor)}
          onClose={() => setAnchorEl(null)}
        >
          <MenuItem
            onClick={() => {
              data.openConfig(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t_i18n('Update')}
          </MenuItem>
          <MenuItem
            onClick={() => {
              data.openReplace(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t_i18n('Replace')}
          </MenuItem>
          {!isEntryPoint && (
            <MenuItem
              onClick={() => {
                data.openAddSibling(getNode(id));
                setAnchorEl(null);
              }}
            >
              {t_i18n('Add a sibling node')}
            </MenuItem>
          )}
          <MenuItem
            onClick={() => {
              data.openDelete(getNode(id));
              setAnchorEl(null);
            }}
          >
            {t_i18n('Delete')}
          </MenuItem>
        </Menu>
      </div>
      {lastExecution && (
        <Tooltip title={`${t_i18n('Last execution')}: ${lastStatusLabel}${lastDuration ? `, ${lastDuration}` : ''}`}>
          <span
            data-testid={`playbook-node-last-execution-${id}`}
            aria-label={`${t_i18n('Last execution')}: ${lastStatusLabel}`}
            style={{
              position: 'absolute',
              top: -10,
              right: 28,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              padding: '1px 8px 1px 4px',
              borderRadius: 10,
              fontSize: 10,
              lineHeight: '16px',
              whiteSpace: 'nowrap',
              color: theme.palette.text?.primary,
              backgroundColor: theme.palette.background.default,
              border: `1px solid ${lastExecution.status === 'success' ? theme.palette.success.main : theme.palette.error.main}`,
            }}
          >
            {lastExecution.status === 'success'
              ? <CheckCircleOutlined color="success" style={{ fontSize: 12 }} />
              : <ErrorOutlined color="error" style={{ fontSize: 12 }} />}
            {lastDuration ?? lastStatusLabel}
          </span>
        </Tooltip>
      )}
      {!isEntryPoint && (
        <Handle type="target" position={target} style={{ background: accent, border: 'none' }} />
      )}
      {ports.map((port, index) => {
        const anchor = portAnchor(index, ports.length, direction);
        return (
          <React.Fragment key={port.id}>
            <Handle
              id={port.id}
              type="source"
              position={source}
              style={{ ...(direction === 'horizontal' ? { top: anchor.y } : { left: anchor.x }), background: accent, border: 'none' }}
            />
            {(ports.length > 1 || port.id !== 'out') && (
              <span
                className="nodrag nopan"
                style={{
                  position: 'absolute',
                  left: anchor.x,
                  top: anchor.y,
                  transform: direction === 'horizontal' ? 'translate(6px, -50%)' : 'translate(-50%, 6px)',
                  padding: '1px 8px',
                  borderRadius: 10,
                  fontSize: 10,
                  lineHeight: '16px',
                  whiteSpace: 'nowrap',
                  color: theme.palette.text?.primary,
                  backgroundColor: theme.palette.background.default,
                  border: `1px solid ${accent}`,
                  pointerEvents: 'none',
                }}
              >
                {t_i18n(port.id)}
              </span>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};

export default memo(NodeWorkflow);
