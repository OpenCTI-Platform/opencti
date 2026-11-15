import React, { memo, useState } from 'react';
import { Handle, NodeProps, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert, LoginOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../../components/i18n';
import { truncate } from '../../../../../../utils/String';
import type { Theme } from '../../../../../../components/Theme';
import { usePlaybookHandlePositions } from '../../hooks/usePlaybookLayoutMode';
import { categoryAccent, outPorts, PLAYBOOK_CARD, portAnchor } from './playbookNodeGeometry';

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
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
  return (
    <div
      data-testid={`playbook-node-${id}`}
      style={{
        position: 'relative',
        boxSizing: 'border-box',
        width: PLAYBOOK_CARD.width,
        height: PLAYBOOK_CARD.height,
        border: `1px solid ${theme.palette.divider}`,
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
      <div style={{ position: 'absolute', top: 4, right: 2 }}>
        <IconButton
          aria-label={t_i18n('Open menu')}
          onClick={(event) => setAnchorEl(event.currentTarget)}
          aria-haspopup="true"
          size="small"
        >
          <MoreVert style={{ fontSize: 16 }} />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
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
      {!isEntryPoint && (
        <div style={{ position: 'absolute', bottom: 2, right: 2 }}>
          <IconButton
            onClick={() => data.openAddSibling(getNode(id))}
            aria-haspopup="true"
            size="small"
            aria-label={t_i18n('Add a sibling node')}
            tooltip={t_i18n('Add a new branch at the same level from the parent output')}
          >
            <LoginOutlined style={{ fontSize: 14 }} />
          </IconButton>
        </div>
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
