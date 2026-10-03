import React, { CSSProperties, useMemo } from 'react';
import { IconButton, Paper, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { UnfoldLessOutlined, UnfoldMoreOutlined, VisibilityOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../ItemIcon';
import { itemColor } from '../../../utils/Colors';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import { linkDash } from '../utils/graphPainting';
import { buildGraphPalette } from '../utils/graphPalette';

export interface GraphLegendProps {
  nodes: readonly GraphNode[];
  links: readonly GraphLink[];
  disabledEntityTypes: readonly string[];
  disabledRelationshipTypes: readonly string[];
  collapsedEntityTypes: readonly string[];
  hiddenCount: number;
  onToggleEntityType: (type: string) => void;
  onToggleRelationshipType: (type: string) => void;
  onToggleCollapsed: (type: string) => void;
  onShowHidden: () => void;
}

const countBy = <T, >(items: readonly T[], key: (item: T) => string) => {
  const counts = new Map<string, number>();
  items.forEach((item) => {
    const value = key(item);
    if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
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
  onToggleEntityType,
  onToggleRelationshipType,
  onToggleCollapsed,
  onShowHidden,
}: GraphLegendProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const palette = useMemo(() => buildGraphPalette(theme), [theme]);

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
    const counts = countBy(links.filter((link) => !!link.label), (link) => link.relationship_type || link.entity_type);
    return [...counts.entries()]
      .map(([type, count]) => ({ type, count, label: t_i18n(`relationship_${type}`) }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  }, [links]);

  const row: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
    width: '100%',
    minHeight: 28,
    padding: theme.spacing(0.25, 0.75),
    border: 'none',
    borderRadius: 4,
    background: 'transparent',
    color: theme.palette.text.primary,
    font: 'inherit',
    fontSize: 12,
    textAlign: 'left',
    cursor: 'pointer',
  };
  const count: CSSProperties = { marginLeft: 'auto', color: theme.palette.text.secondary, fontVariantNumeric: 'tabular-nums' };
  const heading: CSSProperties = {
    margin: theme.spacing(1, 0.75, 0.5),
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: 0.3,
    textTransform: 'uppercase',
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
        position: 'absolute',
        left: theme.spacing(1.5),
        bottom: theme.spacing(1.5),
        zIndex: 2,
        width: 248,
      }}
      onMouseDown={(event) => event.stopPropagation()}
    >
      <div style={{ maxHeight: 'min(45vh, 420px)', overflowY: 'auto', padding: theme.spacing(0.5) }}>
        <div style={heading}>{t_i18n('Entities')}</div>
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
                aria-label={`${label}: ${total}`}
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
                  <ItemIcon type={type} size="inherit" style={{ fontSize: 13 }} />
                </span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: disabled ? 'line-through' : 'none' }}>
                  {label}
                </span>
                <span style={count}>{total}</span>
              </button>
              <Tooltip>
                <TooltipTrigger asChild>
                  <IconButton
                    priority="tertiary"
                    size="sm"
                    aria-label={collapsed ? t_i18n('Expand the group') : t_i18n('Collapse into one node')}
                    aria-pressed={collapsed}
                    active={collapsed}
                    icon={collapsed ? <UnfoldMoreOutlined fontSize="small" /> : <UnfoldLessOutlined fontSize="small" />}
                    onClick={() => onToggleCollapsed(type)}
                  />
                </TooltipTrigger>
                <TooltipContent side="right">
                  {collapsed ? t_i18n('Expand the group') : t_i18n('Collapse into one node')}
                </TooltipContent>
              </Tooltip>
            </div>
          );
        })}
        {relationshipCounts.length > 0 && (
          <>
            <div style={heading}>{t_i18n('Relationships')}</div>
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
        <div style={heading}>{t_i18n('Line styles')}</div>
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
      </div>
    </Paper>
  );
};

export default GraphLegend;
