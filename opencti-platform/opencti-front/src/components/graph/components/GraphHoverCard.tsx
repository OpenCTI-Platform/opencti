import React, { CSSProperties, ReactNode, useLayoutEffect, useRef, useState } from 'react';
import { Paper, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../ItemIcon';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import type { GraphBadge } from '../badges';
import { graphNodeTitle, NO_AUTHOR_ID, NO_MARKING_ID } from '../utils/useGraphParser';
import { buildGraphPalette, dataColorOutline } from '../utils/graphPalette';
import { EXPORT_REMOVE_CLASS } from '../../../utils/Image';
import { isGroupLink } from '../utils/graphCollapse';

export type GraphHoverCardTarget
  = | { kind: 'node'; node: GraphNode }
    | { kind: 'link'; link: GraphLink };

export interface GraphHoverCardProps {
  target: GraphHoverCardTarget;
  anchor: { x: number; y: number };
  bounds: { width: number; height: number };
  context?: string;
  badges: GraphBadge[];
  relationshipCounts: { type: string; count: number }[];
  /** For a group node, its members in reading order: the card previews the first ones. */
  groupMembers?: readonly { id: string; name: string }[];
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

const CARD_WIDTH = 300;
const OFFSET = 16;
const GROUP_PREVIEW_SIZE = 5;
/** The height a card is placed for until it is measured. */
const ESTIMATED_CARD_HEIGHT = 260;

/**
 * What the pointer is on, in words: the canvas shows the shape of the graph, the card names its
 * parts. It only previews; what applies to the element is in the context menu of the graph.
 */
const GraphHoverCard = ({
  target,
  anchor,
  bounds,
  context,
  badges,
  relationshipCounts,
  groupMembers = [],
  onMouseEnter,
  onMouseLeave,
}: GraphHoverCardProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const theme = useTheme<Theme>();
  const palette = buildGraphPalette(theme);

  // Placed for its rendered height, and never taller than the graph: its content scrolls on a short graph.
  const cardRef = useRef<HTMLDivElement>(null);
  const [cardHeight, setCardHeight] = useState(ESTIMATED_CARD_HEIGHT);
  useLayoutEffect(() => {
    const measured = cardRef.current?.offsetHeight;
    if (measured && measured !== cardHeight) setCardHeight(measured);
  });
  const left = anchor.x + OFFSET + CARD_WIDTH > bounds.width ? Math.max(0, anchor.x - OFFSET - CARD_WIDTH) : anchor.x + OFFSET;
  const top = Math.max(0, Math.min(anchor.y + OFFSET, bounds.height - Math.min(cardHeight, bounds.height)));
  const fact: CSSProperties = { display: 'flex', gap: theme.spacing(1) };
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
        <Text variant="content-base-bold" as="div" style={{ overflowWrap: 'anywhere' }}>{title}</Text>
        <div style={{ color: theme.palette.text.secondary }}>{subtitle}</div>
      </div>
    </div>
  );

  let content: ReactNode;
  if (target.kind === 'node' && target.node.groupOf) {
    const { node } = target;
    const { entityType, memberIds } = node.groupOf ?? { entityType: node.entity_type, memberIds: [] };
    const preview = groupMembers.slice(0, GROUP_PREVIEW_SIZE);
    const more = memberIds.length - preview.length;
    content = (
      <>
        {header(entityType, node.label, t_i18n('Group'), node.color)}
        <div style={fact}>
          <span style={factLabel}>{t_i18n('Entities')}</span>
          <span>{memberIds.length}</span>
        </div>
        {preview.length > 0 && (
          <ul aria-label={t_i18n('Members')} style={{ margin: theme.spacing(0.5, 0, 0), paddingLeft: theme.spacing(2) }}>
            {preview.map(({ id, name }) => (
              <li key={id} style={{ overflowWrap: 'anywhere' }}>{name}</li>
            ))}
            {more > 0 && (
              <li style={{ listStyle: 'none', color: theme.palette.text.secondary }}>
                {t_i18n('{count, plural, one {and # more} other {and # more}}', { values: { count: more } })}
              </li>
            )}
          </ul>
        )}
      </>
    );
  } else if (target.kind === 'node') {
    const { node } = target;
    const nodeMarkings = markings(node);
    const typeLabel = node.relationship_type ? t_i18n(`relationship_${node.relationship_type}`) : t_i18n(`entity_${node.entity_type}`);
    content = (
      <>
        {header(node.relationship_type ? 'relationship' : node.entity_type, graphNodeTitle(node), typeLabel, node.color)}
        {node.isRestricted && (
          <div style={{ ...fact, color: theme.palette.text.secondary, marginBottom: theme.spacing(0.5) }}>
            {t_i18n('You do not have access to this entity.')}
          </div>
        )}
        {/* The date of an entity the reader may not see is a placeholder of the platform, not a fact. */}
        {!node.isRestricted && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Date')}</span>
            {dateFact(node.defaultDate)}
          </div>
        )}
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
        {nodeMarkings.length > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Markings')}</span>
            <span style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.75) }}>
              {nodeMarkings.map((marking) => (
                <span key={marking.id} style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(0.5) }}>
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
                    <Text
                      variant="content-caption"
                      role="listitem"
                      tabIndex={0}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: theme.spacing(0.5),
                        border: `1px solid ${outline ?? color}`,
                        borderRadius: 10,
                        padding: theme.spacing(0, 1),
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
                    </Text>
                  </TooltipTrigger>
                  <TooltipContent>{badge.tooltip ?? badge.label}</TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        )}
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
    // A group link stands for several relationships: no fact or action of one of them applies to it.
    const isGroup = isGroupLink(link);
    content = (
      <>
        {header('relationship', t_i18n(`relationship_${type}`), `${sourceLabel} \u2192 ${targetLabel}`, palette.link)}
        {!isGroup && link.defaultDate && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Date')}</span>
            {dateFact(link.defaultDate)}
          </div>
        )}
        {!isGroup && typeof link.confidence === 'number' && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Confidence level')}</span>
            <span>{link.confidence}</span>
          </div>
        )}
        {!isGroup && (link.inferred || link.isNestedInferred) && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Origin')}</span>
            <span style={{ color: palette.inferred }}>{t_i18n('Inferred relationship')}</span>
          </div>
        )}
        {!isGroup && linkMarkings.length > 0 && (
          <div style={fact}>
            <span style={factLabel}>{t_i18n('Markings')}</span>
            <span>{linkMarkings.map((marking) => marking.definition).join(', ')}</span>
          </div>
        )}
      </>
    );
  }

  return (
    <Paper
      ref={cardRef}
      elevation={3}
      padding={16}
      className={EXPORT_REMOVE_CLASS}
      role="group"
      aria-label={t_i18n('Details on hover')}
      data-testid="graph-hover-card"
      style={{ position: 'absolute', left, top, width: CARD_WIDTH, maxHeight: bounds.height, overflowY: 'auto', zIndex: 3 }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onMouseDown={(event) => event.stopPropagation()}
    >
      <Text variant="content-compact" as="div">{content}</Text>
      {!(target.kind === 'link' && isGroupLink(target.link)) && (
        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
          {t_i18n('Right-click for its actions')}
        </Text>
      )}
    </Paper>
  );
};

export default GraphHoverCard;
