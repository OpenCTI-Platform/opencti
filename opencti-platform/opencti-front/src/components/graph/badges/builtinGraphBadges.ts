import { SpeedOutlined } from '@mui/icons-material';
import { AutoFix } from 'mdi-material-ui';
import { type GraphBadgeProvider, registerGraphBadgeProvider } from './graphBadgeRegistry';
import { LOW_CONFIDENCE_THRESHOLD } from '../utils/graphPainting';
import { NO_MARKING_ID } from '../utils/useGraphParser';

/**
 * The markings of a node, at a glance: a dot in the colour of its first marking, with the number
 * of markings when there are several. The hover card names each of them.
 */
export const markingBadgeProvider: GraphBadgeProvider = {
  id: 'markings',
  order: 10,
  badgesFor: (node, { t_i18n }) => {
    const markings = node.markedBy.filter((marking) => marking.id !== NO_MARKING_ID);
    if (markings.length === 0) return [];
    return [{
      key: 'markings',
      tone: 'neutral',
      color: markings[0].x_opencti_color ?? null,
      label: markings.map((marking) => marking.definition).join(', '),
      legendLabel: t_i18n('Markings'),
      value: markings.length > 1 ? markings.length : undefined,
    }];
  },
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
      legendLabel: t_i18n('Low confidence'),
      tooltip: t_i18n('Its confidence level is below {threshold}', { values: { threshold: LOW_CONFIDENCE_THRESHOLD } }),
      value: confidence,
    }];
  },
};

export const inferredBadgeProvider: GraphBadgeProvider = {
  id: 'inferred',
  order: 30,
  badgesFor: (node, { t_i18n }) => (node.isNestedInferred
    ? [{ key: 'inferred', icon: AutoFix, tone: 'warning', label: t_i18n('Inferred'), tooltip: t_i18n('Created by an inference rule') }]
    : []),
};

export const registerBuiltinGraphBadges = () => {
  registerGraphBadgeProvider(markingBadgeProvider);
  registerGraphBadgeProvider(confidenceBadgeProvider);
  registerGraphBadgeProvider(inferredBadgeProvider);
};
