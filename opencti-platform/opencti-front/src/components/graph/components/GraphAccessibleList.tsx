import React, { KeyboardEvent, useId, useMemo, useState } from 'react';
import { useFormatter } from '../../i18n';
import type { GraphLink, GraphNode } from '../graph.types';
import { graphNodeTitle } from '../utils/useGraphParser';
import { badgesOfNode, useGraphBadgeRegistryVersion } from '../badges';

/**
 * Options mounted on each side of the active one. Every element of the graph stays in the list and
 * is reached by moving through it; only a window of options is in the document, so a graph of
 * thousands of elements keeps a light list box.
 */
export const ACCESSIBLE_LIST_WINDOW_RADIUS = 100;

export interface GraphAccessibleListProps {
  nodes: readonly GraphNode[];
  links: readonly GraphLink[];
  selectedIds: ReadonlySet<string>;
  onSelectNode: (node: GraphNode, additive: boolean) => void;
  onSelectLink: (link: GraphLink, additive: boolean) => void;
}

const endpoint = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end : null);

type Entry = { kind: 'node'; node: GraphNode; text: string } | { kind: 'link'; link: GraphLink; text: string };

/**
 * What the canvas draws, said in words. A canvas has no element to focus and nothing to
 * announce, so every entity and relationship drawn is mirrored by an option of a list box that
 * only a keyboard or a screen reader reaches: arrows move, Enter or Space selects like a click on
 * the canvas, with Shift to add to the selection.
 */
const GraphAccessibleList = ({ nodes, links, selectedIds, onSelectNode, onSelectLink }: GraphAccessibleListProps) => {
  const { t_i18n } = useFormatter();
  const badgeRegistryVersion = useGraphBadgeRegistryVersion();
  const listId = useId();
  const [active, setActive] = useState(0);

  const entries = useMemo<Entry[]>(() => {
    const degree = new Map<string, number>();
    links.forEach((link) => {
      // A self-loop is one relationship of its entity.
      new Set([endpoint(link.source)?.id ?? link.source_id, endpoint(link.target)?.id ?? link.target_id]).forEach((id) => {
        degree.set(id, (degree.get(id) ?? 0) + 1);
      });
    });
    const nodeEntries: Entry[] = nodes.map((node) => {
      const type = node.relationship_type ? t_i18n(`relationship_${node.relationship_type}`) : t_i18n(`entity_${node.entity_type}`);
      const name = graphNodeTitle(node);
      const count = t_i18n('{count, plural, one {# relationship} other {# relationships}}', { values: { count: degree.get(node.id) ?? 0 } });
      // Every badge, drawn or not, as the hover card lists them: what the canvas says by colour and icon.
      const badges = node.groupOf ? [] : badgesOfNode(node, { t_i18n }).map((badge) => badge.label);
      return { kind: 'node', node, text: [`${type} ${name}`, count, ...badges].join(', ') };
    });
    const endName = (end: GraphLink['source'], id: string) => {
      const node = endpoint(end);
      return node ? graphNodeTitle(node) : id;
    };
    const linkEntries: Entry[] = links.map((link) => ({
      kind: 'link',
      link,
      text: `${endName(link.source, link.source_id)} ${link.label || t_i18n(`relationship_${link.relationship_type || link.entity_type}`)} ${endName(link.target, link.target_id)}`,
    }));
    return [...nodeEntries, ...linkEntries];
  }, [nodes, links, badgeRegistryVersion]);

  const activeIndex = Math.min(active, Math.max(0, entries.length - 1));
  const windowStart = Math.max(0, activeIndex - ACCESSIBLE_LIST_WINDOW_RADIUS);
  const windowEnd = Math.min(entries.length, activeIndex + ACCESSIBLE_LIST_WINDOW_RADIUS + 1);
  const idOf = (entry: Entry) => (entry.kind === 'node' ? entry.node.id : entry.link.id);
  // A nested relationship is drawn as a node and two connector links that share its id.
  const keyOf = (entry: Entry) => (entry.kind === 'node'
    ? `node:${entry.node.id}`
    : `link:${entry.link.id}:${endpoint(entry.link.source)?.id ?? entry.link.source_id}:${endpoint(entry.link.target)?.id ?? entry.link.target_id}`);
  const choose = (entry: Entry, additive: boolean) => {
    if (entry.kind === 'node') onSelectNode(entry.node, additive);
    else onSelectLink(entry.link, additive);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (entries.length === 0) return;
    const moves: Record<string, number> = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 };
    if (event.key in moves) {
      event.preventDefault();
      event.stopPropagation();
      setActive(Math.max(0, Math.min(entries.length - 1, activeIndex + moves[event.key])));
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      setActive(event.key === 'Home' ? 0 : entries.length - 1);
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      event.stopPropagation();
      choose(entries[activeIndex], event.shiftKey);
    }
  };

  return (
    <div
      className="sr-only"
      role="listbox"
      tabIndex={0}
      aria-multiselectable
      aria-label={t_i18n('Elements of the graph')}
      aria-activedescendant={entries.length > 0 ? `${listId}-${activeIndex}` : undefined}
      onKeyDown={onKeyDown}
    >
      {entries.slice(windowStart, windowEnd).map((entry, offset) => (
        <div
          key={keyOf(entry)}
          id={`${listId}-${windowStart + offset}`}
          role="option"
          aria-selected={selectedIds.has(idOf(entry))}
          aria-posinset={windowStart + offset + 1}
          aria-setsize={entries.length}
          onClick={(event) => choose(entry, event.shiftKey)}
        >
          {entry.text}
        </div>
      ))}
    </div>
  );
};

export default GraphAccessibleList;
