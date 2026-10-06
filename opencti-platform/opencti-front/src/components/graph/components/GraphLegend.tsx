import React, { CSSProperties, useId, useMemo } from 'react';
import { Button, IconButton, Paper, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { LegendToggleOutlined, MinimizeOutlined, UnfoldLessOutlined, UnfoldMoreOutlined, VisibilityOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../ItemIcon';
import { itemColor } from '../../../utils/Colors';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import type { GraphBadgeTone } from '../badges/graphBadgeRegistry';
import { linkDash } from '../utils/graphPainting';
import { buildGraphPalette } from '../utils/graphPalette';

/** A badge drawn in the graph, with the number of entities carrying it. */
export interface GraphLegendBadge {
  key: string;
  label: string;
  tone: GraphBadgeTone;
  tooltip?: string;
  count: number;
}

export interface GraphLegendProps {
  nodes: readonly GraphNode[];
  links: readonly GraphLink[];
  disabledEntityTypes: readonly string[];
  disabledRelationshipTypes: readonly string[];
  collapsedEntityTypes: readonly string[];
  hiddenCount: number;
  /** Only the badges present in the graph. */
  badges?: readonly GraphLegendBadge[];
  /** Pixels the toolbar under the graph covers at the bottom of the canvas, which the legend stays above. */
  bottomOffset?: number;
  /** Height of anything docked at the top of the canvas, which the legend stays under. */
  topOffset?: number;
  onToggleEntityType: (type: string) => void;
  onToggleRelationshipType: (type: string) => void;
  onToggleCollapsed: (type: string) => void;
  onShowHidden: () => void;
  /** Selects the entities carrying the badge. */
  onSelectBadge?: (key: string) => void;
  /** Folds the legend to its pill. */
  onMinimize?: () => void;
}

/** Where the legend and its pill sit: the bottom left corner of the canvas, above the toolbar. */
const cornerStyle = (spacing: string, bottomOffset: number): CSSProperties => ({
  position: 'absolute',
  left: spacing,
  bottom: spacing,
  marginBottom: bottomOffset,
  zIndex: 2,
});

export interface GraphLegendPillProps {
  /** Entity and relationship types filtered out from the legend. */
  filterCount: number;
  bottomOffset?: number;
  onOpen: () => void;
}

/** The legend minimized: one button in its corner, with the number of filters in use. */
export const GraphLegendPill = ({ filterCount, bottomOffset = 0, onOpen }: GraphLegendPillProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const filters = filterCount > 0 ? t_i18n('{count, plural, one {# filter} other {# filters}}', { values: { count: filterCount } }) : null;
  return (
    <Paper
      elevation={2}
      padding={0}
      data-graph-panel=""
      style={cornerStyle(theme.spacing(1.5), bottomOffset)}
      onMouseDown={(event) => event.stopPropagation()}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            priority="tertiary"
            size="sm"
            aria-label={filters ? `${t_i18n('Show the legend')}, ${filters}` : t_i18n('Show the legend')}
            aria-expanded={false}
            aria-keyshortcuts="G"
            startIcon={<LegendToggleOutlined fontSize="small" />}
            onClick={onOpen}
          >
            {t_i18n('Legend')}
            {filters && <span style={{ color: theme.palette.text.secondary }}>{` \u00b7 ${filters}`}</span>}
          </Button>
        </TooltipTrigger>
        <TooltipContent side="top">{`${t_i18n('Show the legend')} (G)`}</TooltipContent>
      </Tooltip>
    </Paper>
  );
};

const countBy = <T, >(items: readonly T[], key: (item: T) => string, weight: (item: T) => number = () => 1) => {
  const counts = new Map<string, number>();
  items.forEach((item) => {
    const value = key(item);
    if (value) counts.set(value, (counts.get(value) ?? 0) + weight(item));
  });
  return counts;
};

/**
 * What the graph is made of, counted: each entity type and relationship type is a filter (a click
 * fades or restores it) and each entity type can be folded into one group node.
 */
const GraphLegend = ({
  nodes,
  links,
  disabledEntityTypes,
  disabledRelationshipTypes,
  collapsedEntityTypes,
  hiddenCount,
  badges = [],
  bottomOffset = 0,
  topOffset = 0,
  onToggleEntityType,
  onToggleRelationshipType,
  onToggleCollapsed,
  onShowHidden,
  onSelectBadge,
  onMinimize,
}: GraphLegendProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const palette = useMemo(() => buildGraphPalette(theme), [theme]);
  const bodyId = useId();

  const entityCounts = useMemo(() => {
    const counts = countBy(
      nodes.flatMap((node) => {
        if (node.groupOf) return node.groupOf.memberIds.map(() => node.groupOf?.entityType ?? '');
        return node.relationship_type ? [] : [node.entity_type];
      }),
      (type) => type,
    );
    return [...counts.entries()]
      .map(([type, count]) => ({ type, count, label: t_i18n(`entity_${type}`) }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  }, [nodes]);

  const relationshipCounts = useMemo(() => {
    const counts = countBy(
      [
        // A link drawn towards a group node counts every relationship it stands for.
        ...links.filter((link) => !!link.label).map((link) => ({ type: link.relationship_type || link.entity_type, count: link.represents ?? 1 })),
        // A nested relationship is drawn as a node between two unlabelled connector links.
        ...nodes.filter((node) => !!node.relationship_type && !node.groupOf).map((node) => ({ type: node.relationship_type, count: 1 })),
      ],
      (entry) => entry.type,
      (entry) => entry.count,
    );
    return [...counts.entries()]
      .map(([type, count]) => ({ type, count, label: t_i18n(`relationship_${type}`) }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  }, [links, nodes]);

  const row: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
    width: '100%',
    minHeight: 28,
    padding: theme.spacing(0.25, 0.75),
    border: 'none',
    borderRadius: theme.borderRadius,
    background: 'transparent',
    color: theme.palette.text.primary,
    font: 'inherit',
    textAlign: 'left',
    cursor: 'pointer',
  };
  const count: CSSProperties = { marginLeft: 'auto', color: theme.palette.text.secondary, fontVariantNumeric: 'tabular-nums' };
  const heading: CSSProperties = {
    margin: theme.spacing(1, 0.75, 0.5),
    color: theme.palette.text.secondary,
  };
  const lineSample = (dash: number[], color: string) => (
    <svg width="22" height="8" aria-hidden style={{ flexShrink: 0 }}>
      <line x1="1" y1="4" x2="21" y2="4" stroke={color} strokeWidth="2" strokeDasharray={dash.map((value) => value * 2.5).join(' ')} strokeLinecap="round" />
    </svg>
  );

  return (
    <Paper
      elevation={2}
      padding={0}
      aria-label={t_i18n('Legend')}
      role="region"
      data-graph-panel=""
      style={{
        ...cornerStyle(theme.spacing(1.5), bottomOffset),
        width: 248,
        display: 'flex',
        flexDirection: 'column',
        maxHeight: `calc(100% - ${theme.spacing(1.5)} - ${topOffset}px - ${theme.spacing(1)} - ${theme.spacing(1.5)} - ${bottomOffset}px)`,
      }}
      onMouseDown={(event) => event.stopPropagation()}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(0.5, 0.5, 0, 1.25) }}>
        <Text variant="content-compact-bold" as="h2" style={{ margin: 0 }}>{t_i18n('Legend')}</Text>
        {onMinimize && (
          <Tooltip>
            <TooltipTrigger asChild>
              <IconButton
                priority="tertiary"
                size="sm"
                aria-label={t_i18n('Minimise the legend')}
                aria-expanded
                aria-controls={bodyId}
                aria-keyshortcuts="G"
                icon={<MinimizeOutlined fontSize="small" />}
                onClick={onMinimize}
              />
            </TooltipTrigger>
            <TooltipContent side="right">{`${t_i18n('Minimise the legend')} (G)`}</TooltipContent>
          </Tooltip>
        )}
      </div>
      <Text id={bodyId} variant="content-compact" as="div" style={{ maxHeight: 'min(45vh, 420px)', overflowY: 'auto', padding: theme.spacing(0, 0.5, 0.5) }}>
        <Text variant="content-compact-bold" as="div" style={heading}>{t_i18n('Entities')}</Text>
        {entityCounts.map(({ type, count: total, label }) => {
          const disabled = disabledEntityTypes.includes(type);
          const collapsed = collapsedEntityTypes.includes(type);
          const color = itemColor(type);
          return (
            <div key={type} style={{ display: 'flex', alignItems: 'center' }}>
              <button
                type="button"
                style={{ ...row, opacity: disabled ? 0.45 : 1 }}
                aria-pressed={!disabled}
                aria-label={`${collapsed ? t_i18n('Group: {type}', { values: { type: label } }) : label}: ${total}`}
                onClick={() => onToggleEntityType(type)}
              >
                <span
                  aria-hidden
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 20,
                    height: 20,
                    flexShrink: 0,
                    borderRadius: '50%',
                    border: `1.5px solid ${color}`,
                    backgroundColor: `color-mix(in srgb, ${color} 22%, transparent)`,
                  }}
                >
                  <ItemIcon type={type} size="inherit" style={{ width: 13, height: 13 }} />
                </span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: disabled ? 'line-through' : 'none' }}>
                  {collapsed ? t_i18n('Group: {type}', { values: { type: label } }) : label}
                </span>
                <span style={count}>{total}</span>
              </button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <IconButton
                    priority="tertiary"
                    size="sm"
                    aria-label={collapsed ? t_i18n('Ungroup') : t_i18n('Group by type')}
                    aria-pressed={collapsed}
                    active={collapsed}
                    icon={collapsed ? <UnfoldMoreOutlined fontSize="small" /> : <UnfoldLessOutlined fontSize="small" />}
                    onClick={() => onToggleCollapsed(type)}
                  />
                </TooltipTrigger>
                <TooltipContent side="right">
                  {collapsed ? t_i18n('Ungroup') : t_i18n('Group by type')}
                </TooltipContent>
              </Tooltip>
            </div>
          );
        })}
        {relationshipCounts.length > 0 && (
          <>
            <Text variant="content-compact-bold" as="div" style={heading}>{t_i18n('Relationships')}</Text>
            {relationshipCounts.map(({ type, count: total, label }) => {
              const disabled = disabledRelationshipTypes.includes(type);
              return (
                <button
                  key={type}
                  type="button"
                  style={{ ...row, opacity: disabled ? 0.45 : 1 }}
                  aria-pressed={!disabled}
                  aria-label={`${label}: ${total}`}
                  onClick={() => onToggleRelationshipType(type)}
                >
                  {lineSample([], palette.link)}
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: disabled ? 'line-through' : 'none' }}>
                    {label}
                  </span>
                  <span style={count}>{total}</span>
                </button>
              );
            })}
          </>
        )}
        {badges.length > 0 && (
          <>
            <Text variant="content-compact-bold" as="div" style={heading}>{t_i18n('Badges')}</Text>
            {badges.map(({ key, label, tone, tooltip, count: total }) => (
              <Tooltip key={key}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    style={row}
                    aria-label={`${label}: ${total}`}
                    onClick={() => onSelectBadge?.(key)}
                  >
                    <span aria-hidden style={{ width: 22, display: 'inline-flex', justifyContent: 'center', flexShrink: 0 }}>
                      <span style={{ width: 10, height: 10, borderRadius: '50%', border: `2px solid ${palette.tones[tone]}` }} />
                    </span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                    <span style={count}>{total}</span>
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right">{tooltip ?? label}</TooltipContent>
              </Tooltip>
            ))}
          </>
        )}
        <Text variant="content-compact-bold" as="div" style={heading}>{t_i18n('Line styles')}</Text>
        <div style={{ ...row, cursor: 'default' }}>
          {lineSample([], palette.link)}
          {t_i18n('Asserted relationship')}
        </div>
        <div style={{ ...row, cursor: 'default' }}>
          {lineSample(linkDash({ inferred: true, isNestedInferred: false }), palette.inferred)}
          {t_i18n('Inferred relationship')}
        </div>
        <div style={{ ...row, cursor: 'default' }}>
          {lineSample(linkDash({ inferred: false, isNestedInferred: false }, 0), palette.link)}
          {t_i18n('Low confidence')}
        </div>
        {hiddenCount > 0 && (
          <button type="button" style={{ ...row, color: palette.accent }} onClick={onShowHidden}>
            <VisibilityOutlined fontSize="small" />
            {t_i18n('Show the hidden entities')}
            <span style={count}>{hiddenCount}</span>
          </button>
        )}
      </Text>
    </Paper>
  );
};

export default GraphLegend;
