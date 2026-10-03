import { CallSplitOutlined, HistoryToggleOffOutlined } from '@mui/icons-material';
import { type GraphBadge, type GraphBadgeProvider, registerGraphBadgeProvider } from '../../../../components/graph/badges/graphBadgeRegistry';

/** Provenance fields the graph queries fetch; absent on graphs that do not. */
interface ProvenanceGraphFields {
  freshness_stale?: boolean | null;
  has_conflicts?: boolean | null;
}

/**
 * Provenance states of an element drawn in a graph: stale knowledge and source conflicts.
 * The corroboration of an element is drawn by the graph itself, as a ring around the node.
 */
export const provenanceGraphBadgeProvider: GraphBadgeProvider = {
  id: 'provenance',
  order: 40,
  badgesFor: (node, { t_i18n }) => {
    const fields = node.raw as ProvenanceGraphFields | undefined;
    const badges: GraphBadge[] = [];
    if (fields?.freshness_stale === true) {
      badges.push({ key: 'provenance-stale', icon: HistoryToggleOffOutlined, tone: 'warning', label: t_i18n('Stale knowledge') });
    }
    if (fields?.has_conflicts === true) {
      badges.push({ key: 'provenance-conflicts', icon: CallSplitOutlined, tone: 'error', label: t_i18n('Has source conflicts') });
    }
    return badges;
  },
};

export const registerProvenanceGraphBadges = () => registerGraphBadgeProvider(provenanceGraphBadgeProvider);
