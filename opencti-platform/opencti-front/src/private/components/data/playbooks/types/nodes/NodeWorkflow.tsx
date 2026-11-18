import React, { memo, useId, useState } from 'react';
import { Handle, NodeProps, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert, CheckCircleOutlined, ErrorOutlined, WarningAmberOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../../components/i18n';
import { truncate } from '../../../../../../utils/String';
import type { Theme } from '../../../../../../components/Theme';
import { usePlaybookHandlePositions } from '../../hooks/usePlaybookLayoutMode';
import { categoryAccent, outPorts, PLAYBOOK_CARD, PLAYBOOK_PORT_PILL_MAX_WIDTH, portAnchor, portHasPill } from './playbookNodeGeometry';
import { usePlaybookNodeLastExecution } from '../../hooks/usePlaybookLastExecution';
import { formatStepDuration } from '../../utils/playbookLastExecution';
import { playbookNodeSummary, type PlaybookNodeSummary } from '../../utils/playbookNodeSummary';
import { usePlaybookCanvasAffordances } from '../../hooks/usePlaybookEditMode';

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
  // View mode: the card shows the step, a click opens nothing and it carries no menu.
  const { nodeMenu, nodeOpensSettings } = usePlaybookCanvasAffordances();
  const component = data.component;
  const accent = categoryAccent(theme, component?.category);
  const displayDescription = data.description || component?.description;
  // A step whose component is not in the catalog keeps a handle on each port its links leave from.
  const ports: { id: string; type: string }[] = component
    ? outPorts(component.ports)
    : (data.linkedPorts ?? []).map((portId: string) => ({ id: portId, type: 'out' }));
  const isEntryPoint = Boolean(component?.is_entry_point);
  const isEnd = ports.length === 0;
  // A step whose component is not in the catalog (an AI agent component without XTM One, a removed
  // connector) still renders, flagged, instead of throwing on an empty translation id.
  const translated = (value: string | null | undefined) => (value ? t_i18n(value) : '');
  const isUnavailable = !component;
  const kind = isUnavailable
    ? t_i18n('Component unavailable')
    : (isEntryPoint ? t_i18n('Trigger') : (isEnd ? t_i18n('End of playbook') : translated(component.category)));
  const muted = theme.palette.text?.secondary;
  const summary = playbookNodeSummary(data.configuration as Record<string, unknown> | undefined, component?.configuration_schema);
  const summaryText = (s: PlaybookNodeSummary): string => {
    switch (s.kind) {
      case 'missing':
        return t_i18n('Configuration required');
      case 'filters':
        return t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: s.count } });
      case 'actions':
        return t_i18n('{count, plural, one {# action} other {# actions}}', { values: { count: s.count } });
      default:
        return `${t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: s.filters } })}, ${t_i18n('{count, plural, one {# action} other {# actions}}', { values: { count: s.actions } })}`;
    }
  };
  // A click anywhere on the card opens its configuration; for the keyboard and screen readers the title
  // is the button that does it, so the card itself is not interactive and the menu is its sibling.
  const openConfiguration = () => {
    if (nodeOpensSettings) data.openConfig(getNode(id));
  };
  // What a screen reader reads after the title button: the summary line and the last execution.
  const descriptionId = useId();
  const spokenDescription = [
    summary ? summaryText(summary) : null,
    lastExecution ? `${t_i18n('Last execution')}: ${lastStatusLabel}${lastDuration ? `, ${lastDuration}` : ''}` : null,
  ].filter(Boolean).join('. ');
  const titleStyle: React.CSSProperties = { marginTop: 4, fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };
  const titleText = translated(truncate(data.name ?? '', 60, false));
  return (
    // The click is a mouse shortcut of the title button, which carries the keyboard path.
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div
      data-testid={`playbook-node-${id}`}
      onClick={openConfiguration}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onContextMenu={(event) => {
        if (!nodeMenu) return;
        event.preventDefault();
        setAnchor({ top: event.clientY, left: event.clientX });
      }}
      style={{
        position: 'relative',
        boxSizing: 'border-box',
        width: PLAYBOOK_CARD.width,
        height: PLAYBOOK_CARD.height,
        cursor: nodeOpensSettings ? 'pointer' : 'default',
        // The outline and the accent stripe are inset shadows, not borders: React Flow places the handles
        // in the padding box, so a 4 px left border moved the target handle 1.5 px off the card centre.
        border: 'none',
        transition: 'box-shadow 120ms',
        borderRadius: isEntryPoint ? 16 : 6,
        backgroundColor: theme.palette.background.paper,
        boxShadow: [
          `inset 4px 0 0 0 ${accent}`,
          `inset 0 0 0 1px ${hovered ? accent : theme.palette.divider}`,
          theme.shadows?.[1],
        ].filter(Boolean).join(', '),
        padding: '11px 33px 11px 16px',
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
      <Tooltip title={translated(data.name)}>
        {nodeOpensSettings ? (
          <button
            type="button"
            data-testid={`playbook-node-open-${id}`}
            aria-label={`${t_i18n('Update')}: ${translated(data.name)}`}
            aria-describedby={spokenDescription ? descriptionId : undefined}
            onClick={(event) => {
              event.stopPropagation();
              openConfiguration();
            }}
            style={{
              ...titleStyle,
              display: 'block',
              width: '100%',
              padding: 0,
              border: 'none',
              background: 'none',
              color: 'inherit',
              font: 'inherit',
              fontSize: titleStyle.fontSize,
              fontWeight: titleStyle.fontWeight,
              textAlign: 'left',
              cursor: 'pointer',
            }}
          >
            {titleText}
          </button>
        ) : (
          <div style={titleStyle}>{titleText}</div>
        )}
      </Tooltip>
      {spokenDescription && (
        <span id={descriptionId} style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap' }}>
          {spokenDescription}
        </span>
      )}
      <Tooltip title={translated(displayDescription)}>
        <div style={{
          marginTop: 2,
          fontSize: 11,
          lineHeight: '14px',
          color: muted,
          display: '-webkit-box',
          // With a summary line, the description keeps one line so every card stays the same height.
          WebkitLineClamp: summary ? 1 : 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
        >
          {translated(displayDescription)}
        </div>
      </Tooltip>
      {summary && (
        <div
          data-testid={`playbook-node-summary-${id}`}
          style={{
            marginTop: 4,
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 11,
            lineHeight: '14px',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            // The text keeps the primary colour (the warning orange on white is 3.1:1 at 11 px, under
            // the 4.5:1 of body text): the warning tone is carried by the icon, a non-text cue.
            color: theme.palette.text?.primary,
          }}
        >
          {summary.kind === 'missing' && (
            <WarningAmberOutlined
              style={{ fontSize: 12, color: (theme.palette.warning as { main?: string } | undefined)?.main }}
            />
          )}
          {summaryText(summary)}
        </div>
      )}
      {nodeMenu && (
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
      )}
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
              // The horizontal pill caps its label at PLAYBOOK_PORT_PILL_MAX_WIDTH and lets pointer events
              // through to this handle, so the full port name is read here on hover.
              title={t_i18n(port.id)}
              style={{ ...(direction === 'horizontal' ? { top: anchor.y } : { left: anchor.x }), background: accent, border: 'none' }}
            />
            {portHasPill(port.id, ports.length) && (
              // The pill sits on the card edge, centred on its port: the link leaves from under it, so
              // no label is ever drawn over a link.
              <span
                className="nodrag nopan"
                data-testid={`playbook-port-${id}-${port.id}`}
                style={{
                  position: 'absolute',
                  left: anchor.x,
                  top: anchor.y,
                  zIndex: 1,
                  transform: 'translate(-50%, -50%)',
                  padding: '1px 8px',
                  borderRadius: 10,
                  fontSize: 10,
                  lineHeight: '16px',
                  whiteSpace: 'nowrap',
                  ...(direction === 'horizontal' && {
                    boxSizing: 'border-box',
                    maxWidth: PLAYBOOK_PORT_PILL_MAX_WIDTH,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }),
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
