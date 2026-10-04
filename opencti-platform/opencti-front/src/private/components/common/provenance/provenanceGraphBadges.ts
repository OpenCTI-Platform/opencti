import { CallSplitOutlined, HistoryToggleOffOutlined } from '@mui/icons-material';
import { type GraphBadgeProvider, registerGraphBadgeProvider } from '../../../../components/graph/badges/graphBadgeRegistry';

/** Provenance fields the graph queries fetch; absent on graphs that do not. */
interface ProvenanceGraphFields {
  freshness_stale?: boolean | null;
  has_conflicts?: boolean | null;
}

/*
 * Provenance states of an element drawn in a graph, one provider each so that both can show on
 * the same node. The corroboration of an element is drawn by the graph itself, as a ring around
 * the node.
 */

export const staleKnowledgeGraphBadgeProvider: GraphBadgeProvider = {
  id: 'provenance-stale',
  order: 40,
  badgesFor: (node, { t_i18n }) => ((node.raw as ProvenanceGraphFields | undefined)?.freshness_stale === true
    ? [{
        key: 'provenance-stale',
        icon: HistoryToggleOffOutlined,
        tone: 'warning',
        label: t_i18n('Stale knowledge'),
        tooltip: t_i18n('No source has asserted it during the stale period'),
      }]
    : []),
};

export const sourceConflictsGraphBadgeProvider: GraphBadgeProvider = {
  id: 'provenance-conflicts',
  order: 41,
  badgesFor: (node, { t_i18n }) => ((node.raw as ProvenanceGraphFields | undefined)?.has_conflicts === true
    ? [{
        key: 'provenance-conflicts',
        icon: CallSplitOutlined,
        tone: 'error',
        label: t_i18n('Has source conflicts'),
        tooltip: t_i18n('Its sources assert conflicting values'),
      }]
    : []),
};

export const registerProvenanceGraphBadges = () => {
  registerGraphBadgeProvider(staleKnowledgeGraphBadgeProvider);
  registerGraphBadgeProvider(sourceConflictsGraphBadgeProvider);
};
