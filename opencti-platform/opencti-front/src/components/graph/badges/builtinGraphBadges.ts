import { SpeedOutlined } from '@mui/icons-material';
import { AutoFix } from 'mdi-material-ui';
import { type GraphBadge, type GraphBadgeProvider, registerGraphBadgeProvider } from './graphBadgeRegistry';
import { LOW_CONFIDENCE_THRESHOLD } from '../utils/graphPainting';
import { NO_MARKING_ID } from '../utils/useGraphParser';

const MAX_MARKING_BADGES = 3;

/** One dot per marking, in the marking's own colour: what may be shared, at a glance. */
export const markingBadgeProvider: GraphBadgeProvider = {
  id: 'markings',
  order: 10,
  badgesFor: (node) => node.markedBy
    .filter((marking) => marking.id !== NO_MARKING_ID)
    .slice(0, MAX_MARKING_BADGES)
    .map((marking): GraphBadge => ({
      key: `marking-${marking.id}`,
      tone: 'neutral',
      color: marking.x_opencti_color ?? null,
      label: marking.definition,
    })),
};

/** Only a low confidence is worth a badge: the hover card gives the value of every node. */
export const confidenceBadgeProvider: GraphBadgeProvider = {
  id: 'confidence',
  order: 20,
  badgesFor: (node, { t_i18n }) => {
    const { confidence } = node;
    if (typeof confidence !== 'number' || confidence >= LOW_CONFIDENCE_THRESHOLD) return [];
    return [{
      key: 'confidence',
      icon: SpeedOutlined,
      tone: 'warning',
      label: `${t_i18n('Low confidence')} (${confidence})`,
      value: confidence,
    }];
  },
};

export const inferredBadgeProvider: GraphBadgeProvider = {
  id: 'inferred',
  order: 30,
  badgesFor: (node, { t_i18n }) => (node.isNestedInferred
    ? [{ key: 'inferred', icon: AutoFix, tone: 'warning', label: t_i18n('Inferred') }]
    : []),
};

export const registerBuiltinGraphBadges = () => {
  registerGraphBadgeProvider(markingBadgeProvider);
  registerGraphBadgeProvider(confidenceBadgeProvider);
  registerGraphBadgeProvider(inferredBadgeProvider);
};
