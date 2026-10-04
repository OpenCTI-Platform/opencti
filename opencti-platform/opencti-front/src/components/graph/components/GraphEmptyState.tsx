import React from 'react';
import { Button, Paper, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';

/** Why nothing is drawn: no data yet, every entity filtered out, or every entity hidden. */
export type GraphEmptyKind = 'empty' | 'filtered' | 'hidden';

const GRAPHS_DOCUMENTATION = 'https://docs.opencti.io/latest/usage/graphs/';

export interface GraphEmptyStateProps {
  kind: GraphEmptyKind;
  /** The graph surface (`investigation`, `correlation`, `analyses`, or none for container knowledge). */
  context?: string;
  onClearFilters: () => void;
  onShowHidden: () => void;
}

/**
 * Says why the graph draws nothing and offers the next action: the documentation on first use,
 * clearing the filters when they leave nothing, showing the entities hidden from the view.
 */
const GraphEmptyState = ({ kind, context, onClearFilters, onShowHidden }: GraphEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const firstUse: Record<string, string> = {
    investigation: t_i18n('Add entities to this investigation from the toolbar, then expand them to follow their relationships.'),
    analyses: t_i18n('No container contains this entity yet.'),
    correlation: t_i18n('No other container shares an entity with this one.'),
  };
  const content: Record<GraphEmptyKind, { title: string; text: string }> = {
    empty: {
      title: t_i18n('Nothing to draw yet'),
      text: firstUse[context ?? ''] ?? t_i18n('Add entities and relationships to this container from the toolbar, or from its Entities and Observables tabs.'),
    },
    filtered: {
      title: t_i18n('No entity matches these filters'),
      text: t_i18n('The types, markings, authors or time range selected in the toolbar leave no entity of the graph.'),
    },
    hidden: {
      title: t_i18n('Every entity is hidden'),
      text: t_i18n('Entities hidden from the view are still part of the graph.'),
    },
  };
  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        pointerEvents: 'none',
        zIndex: 1,
      }}
    >
      <Paper
        elevation={1}
        padding={24}
        role="status"
        style={{ maxWidth: 440, textAlign: 'center', pointerEvents: 'auto' }}
      >
        <Text variant="title-sm" as="div" style={{ marginBottom: theme.spacing(1) }}>{content[kind].title}</Text>
        <Text variant="content-compact" as="div" style={{ color: theme.palette.text.secondary, marginBottom: theme.spacing(2) }}>
          {content[kind].text}
        </Text>
        {kind === 'filtered' && (
          <Button priority="primary" size="sm" onClick={onClearFilters}>{t_i18n('Clear filters')}</Button>
        )}
        {kind === 'hidden' && (
          <Button priority="primary" size="sm" onClick={onShowHidden}>{t_i18n('Show the hidden entities')}</Button>
        )}
        {kind === 'empty' && (
          <Button asChild priority="secondary" size="sm">
            <a href={GRAPHS_DOCUMENTATION} target="_blank" rel="noopener noreferrer">{t_i18n('Read the documentation')}</a>
          </Button>
        )}
      </Paper>
    </div>
  );
};

export default GraphEmptyState;
