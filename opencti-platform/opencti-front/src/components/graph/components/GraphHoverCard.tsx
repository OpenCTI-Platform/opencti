import React, { CSSProperties, ReactNode } from 'react';
import { IconButton, Paper, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import {
  AccountTreeOutlined,
  HubOutlined,
  LinkOutlined,
  ManageSearchOutlined,
  OpenInNewOutlined,
  PushPinOutlined,
  RouteOutlined,
  TrackChangesOutlined,
  UnfoldMoreOutlined,
  VisibilityOffOutlined,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../ItemIcon';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import { type GraphBadge, graphNodeActionsFor, useGraphNodeActionRegistryVersion } from '../badges';
import { graphNodeTitle, NO_AUTHOR_ID, NO_MARKING_ID } from '../utils/useGraphParser';
import { buildGraphPalette, dataColorOutline } from '../utils/graphPalette';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';

export type GraphHoverCardTarget
  = | { kind: 'node'; node: GraphNode }
    | { kind: 'link'; link: GraphLink };

export interface GraphHoverCardActions {
  onOpen: (id: string) => void;
  onExpand?: (node: GraphNode) => void;
  onTogglePin: (node: GraphNode) => void;
  onHide: (node: GraphNode) => void;
  onSelectNeighbours: (node: GraphNode) => void;
  onCentreRadial: (node: GraphNode) => void;
  onPathFromSelection?: (node: GraphNode) => void;
  onRelateToSelection?: (node: GraphNode) => void;
  onStartInvestigation?: (node: GraphNode) => void;
  onExpandGroup: (entityType: string) => void;
  onSelectLink: (link: GraphLink) => void;
}

export interface GraphHoverCardProps {
  target: GraphHoverCardTarget;
  anchor: { x: number; y: number };
  bounds: { width: number; height: number };
  context?: string;
  badges: GraphBadge[];
  relationshipCounts: { type: string; count: number }[];
  isPinned: boolean;
  actions: GraphHoverCardActions;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

const CARD_WIDTH = 300;
const OFFSET = 16;

const Action = ({ label, icon, onClick }: { label: string; icon: ReactNode; onClick: () => void }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <IconButton priority="tertiary" size="sm" aria-label={label} icon={icon} onClick={onClick} />
    </TooltipTrigger>
    <TooltipContent>{label}</TooltipContent>
  </Tooltip>
);

/**
 * What the pointer is on, in words, with the actions that apply to it: the canvas shows the
 * shape of the graph, the card names its parts.
 */
const GraphHoverCard = ({
  target,
  anchor,
  bounds,
  context,
  badges,
  relationshipCounts,
  isPinned,
  actions,
  onMouseEnter,
  onMouseLeave,
}: GraphHoverCardProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const theme = useTheme<Theme>();
  const palette = buildGraphPalette(theme);
  useGraphNodeActionRegistryVersion();

  const left = anchor.x + OFFSET + CARD_WIDTH > bounds.width ? Math.max(0, anchor.x - OFFSET - CARD_WIDTH) : anchor.x + OFFSET;
  const top = Math.max(0, Math.min(anchor.y + OFFSET, bounds.height - 260));
  const fact: CSSProperties = { display: 'flex', gap: theme.spacing(1), fontSize: 12, lineHeight: '18px' };
  const factLabel: CSSProperties = { color: theme.palette.text.secondary, minWidth: 92 };
  // How long ago, the exact date in the tooltip.
  const dateFact = (date: Date | string) => (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0}>{rd(date)}</span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
  const markings = (element: GraphNode | GraphLink) => element.markedBy.filter((m) => m.id !== NO_MARKING_ID);

  const header = (type: string, title: string, subtitle: string, color: string) => (
    <div style={{ display: 'flex', gap: theme.spacing(1.25), alignItems: 'center', marginBottom: theme.spacing(1) }}>
      <span
        aria-hidden
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 32,
          height: 32,
          flexShrink: 0,
          borderRadius: '50%',
          border: `2px solid ${color}`,
          backgroundColor: `color-mix(in srgb, ${color} 22%, transparent)`,
        }}
      >
        <ItemIcon type={type} size="small" color={color} />
      </span>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 14, overflowWrap: 'anywhere' }}>{title}</div>
        <div style={{ fontSize: 12, color: theme.palette.text.secondary }}>{subtitle}</div>
      </div>
    </div>
  );

  let content: ReactNode;
  if (target.kind === 'node' && target.node.groupOf) {
    const { node } = target;
    const { entityType, memberIds } = node.groupOf ?? { entityType: node.entity_type, memberIds: [] };
    content = (
      <>
        {header(entityType, node.label, t_i18n('Collapsed group'), node.color)}
        <div style={fact}>
          <span style={factLabel}>{t_i18n('Entities')}</span>
          <span>{memberIds.length}</span>
        </div>
        <div style={{ display: 'flex', gap: 2, marginTop: theme.spacing(1) }}>
          <Action label={t_i18n('Expand the group')} icon={<UnfoldMoreOutlined fontSize="small" />} onClick={() => actions.onExpandGroup(entityType)} />
        </div>
      </>
    );
  } else if (target.kind === 'node') {
    const { node } = target;
    const nodeMarkings = markings(node);
    const extra = graphNodeActionsFor(node, context);
    const typeLabel = node.relationship_type ? t_i18n(`relationship_${node.relationship_type}`) : t_i18n(`entity_${node.entity_type}`);
    content = (
      <>
        {header(node.relationship_type ? 'relationship' : node.entity_type, graphNodeTitle(node), typeLabel, node.color)}
        {node.isRestricted && (
          <div style={{ ...fact, color: theme.palette.text.secondary, marginBottom: theme.spacing(0.5) }}>
            {t_i18n('You do not have access to this entity.')}
          </div>
        )}
        <div style={fact}>
          <span style={factLabel}>{t_i18n('Date')}</span>
          {dateFact(node.defaultDate)}
        </div>
        {node.createdBy?.name && node.createdBy.id !== NO_AUTHOR_ID && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Author')}</span>
            <span style={{ overflowWrap: 'anywhere' }}>{node.createdBy.name}</span>
          </div>
        )}
        {typeof node.confidence === 'number' && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Confidence level')}</span>
            <span>{node.confidence}</span>
          </div>
        )}
        {typeof node.corroborationCount === 'number' && node.corroborationCount > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Sources')}</span>
            <span>{t_i18n('{count, plural, one {# source} other {# sources}}', { values: { count: node.corroborationCount } })}</span>
          </div>
        )}
        {nodeMarkings.length > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Markings')}</span>
            <span style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {nodeMarkings.map((marking) => (
                <span key={marking.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <span aria-hidden style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: marking.x_opencti_color ?? theme.palette.text.secondary }} />
                  {marking.definition}
                </span>
              ))}
            </span>
          </div>
        )}
        <div style={fact}>
          <span style={factLabel}>{t_i18n('Relationships')}</span>
          <span>
            {relationshipCounts.length === 0
              ? '-'
              : relationshipCounts.slice(0, 4).map(({ type, count }) => `${t_i18n(`relationship_${type}`)} (${count})`).join(', ')}
          </span>
        </div>
        {context === 'investigation' && node.numberOfConnectedElement !== undefined && node.numberOfConnectedElement > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Not displayed')}</span>
            <span>{t_i18n('{count, plural, one {# more connection} other {# more connections}}', { values: { count: node.numberOfConnectedElement } })}</span>
          </div>
        )}
        {badges.length > 0 && (
          <div role="list" aria-label={t_i18n('Badges')} style={{ ...fact, flexWrap: 'wrap', marginTop: theme.spacing(0.5) }}>
            {badges.map((badge) => {
              const color = badge.color || palette.tones[badge.tone];
              const outline = badge.color ? dataColorOutline(badge.color, palette) : null;
              return (
                <Tooltip key={badge.key}>
                  <TooltipTrigger asChild>
                    <span
                      role="listitem"
                      tabIndex={0}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        border: `1px solid ${outline ?? color}`,
                        borderRadius: 10,
                        padding: theme.spacing(0, 1),
                        fontSize: 11,
                      }}
                    >
                      <span
                        aria-hidden
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: '50%',
                          backgroundColor: color,
                          boxShadow: outline ? `0 0 0 1px ${outline}` : undefined,
                        }}
                      />
                      {badge.label}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>{badge.tooltip ?? badge.label}</TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        )}
        <div role="group" aria-label={t_i18n('Quick actions')} style={{ display: 'flex', flexWrap: 'wrap', gap: 2, marginTop: theme.spacing(1) }}>
          {!node.relationship_type && (
            <Action label={t_i18n('Open in a new tab')} icon={<OpenInNewOutlined fontSize="small" />} onClick={() => actions.onOpen(node.id)} />
          )}
          {actions.onExpand && (
            <Action label={t_i18n('Expand this entity')} icon={<AccountTreeOutlined fontSize="small" />} onClick={() => actions.onExpand?.(node)} />
          )}
          <Action
            label={isPinned ? t_i18n('Unpin') : t_i18n('Pin at its place')}
            icon={<PushPinOutlined fontSize="small" />}
            onClick={() => actions.onTogglePin(node)}
          />
          <Action label={t_i18n('Hide from the view')} icon={<VisibilityOffOutlined fontSize="small" />} onClick={() => actions.onHide(node)} />
          <Action label={t_i18n('Select with its neighbours')} icon={<HubOutlined fontSize="small" />} onClick={() => actions.onSelectNeighbours(node)} />
          <Action label={t_i18n('Lay out the graph around it')} icon={<TrackChangesOutlined fontSize="small" />} onClick={() => actions.onCentreRadial(node)} />
          {actions.onPathFromSelection && (
            <Action label={t_i18n('Shortest path from the selection')} icon={<RouteOutlined fontSize="small" />} onClick={() => actions.onPathFromSelection?.(node)} />
          )}
          {actions.onRelateToSelection && (
            <Action label={t_i18n('Create a relationship from the selection')} icon={<LinkOutlined fontSize="small" />} onClick={() => actions.onRelateToSelection?.(node)} />
          )}
          {actions.onStartInvestigation && !node.relationship_type && (
            <Action label={t_i18n('Start an investigation')} icon={<ManageSearchOutlined fontSize="small" />} onClick={() => actions.onStartInvestigation?.(node)} />
          )}
          {extra.map((action) => {
            const Icon = action.icon;
            const label = action.label(t_i18n);
            return (
              <Action
                key={action.id}
                label={label}
                icon={<Icon fontSize="small" />}
                onClick={() => {
                  if (action.href) window.open(action.href(node), '_blank', 'noopener,noreferrer');
                  else action.onSelect?.(node);
                }}
              />
            );
          })}
        </div>
      </>
    );
  } else {
    const { link } = target;
    const source = typeof link.source === 'object' ? link.source : null;
    const sourceLabel = source ? source.label : link.source_id;
    const targetNode = typeof link.target === 'object' ? link.target : null;
    const targetLabel = targetNode ? targetNode.label : link.target_id;
    const linkMarkings = markings(link);
    const type = link.relationship_type || link.entity_type;
    const canOpen = link.entity_type !== 'basic-relationship' && !!link.label;
    content = (
      <>
        {header('relationship', t_i18n(`relationship_${type}`), `${sourceLabel} \u2192 ${targetLabel}`, palette.link)}
        {link.defaultDate && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Date')}</span>
            {dateFact(link.defaultDate)}
          </div>
        )}
        {typeof link.confidence === 'number' && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Confidence level')}</span>
            <span>{link.confidence}</span>
          </div>
        )}
        {typeof link.corroborationCount === 'number' && link.corroborationCount > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Sources')}</span>
            <span>{t_i18n('{count, plural, one {# source} other {# sources}}', { values: { count: link.corroborationCount } })}</span>
          </div>
        )}
        {(link.inferred || link.isNestedInferred) && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Origin')}</span>
            <span style={{ color: palette.inferred }}>{t_i18n('Inferred relationship')}</span>
          </div>
        )}
        {linkMarkings.length > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Markings')}</span>
            <span>{linkMarkings.map((marking) => marking.definition).join(', ')}</span>
          </div>
        )}
        <div role="group" aria-label={t_i18n('Quick actions')} style={{ display: 'flex', gap: 2, marginTop: theme.spacing(1) }}>
          {canOpen && (
            <Action label={t_i18n('Open in a new tab')} icon={<OpenInNewOutlined fontSize="small" />} onClick={() => actions.onOpen(link.id)} />
          )}
          <Action label={t_i18n('Select this relationship')} icon={<LinkOutlined fontSize="small" />} onClick={() => actions.onSelectLink(link)} />
        </div>
      </>
    );
  }

  return (
    <Paper
      elevation={3}
      padding={16}
      className={EXPORT_REMOVE_CLASS}
      role="group"
      aria-label={t_i18n('Details on hover')}
      data-testid="graph-hover-card"
      style={{ position: 'absolute', left, top, width: CARD_WIDTH, zIndex: 3 }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onMouseDown={(event) => event.stopPropagation()}
    >
      {content}
    </Paper>
  );
};

export default GraphHoverCard;
