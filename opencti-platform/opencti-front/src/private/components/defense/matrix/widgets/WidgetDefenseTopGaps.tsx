import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, List, ListItem, ListItemText } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Chip } from '@filigran/design-system';
import type { Theme } from '../../../../../components/Theme';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { DEFENSE_ACTION_LABELS, DEFENSE_UNCOVERED_LEVELS, type DefenseAction, defenseLevelColor, defenseLevelLabel } from '../defenseMatrix-utils';
import { WidgetDefenseTopGapsQuery } from './__generated__/WidgetDefenseTopGapsQuery.graphql';
import DefenseWidgetContainer from './DefenseWidgetContainer';

const TOP_GAPS = 10;

const widgetDefenseTopGapsQuery = graphql`
  query WidgetDefenseTopGapsQuery($first: Int, $levels: [Int!]) {
    defenseGaps(threatScope: { mode: ALL }, filter: { levels: $levels, onlyUsedByThreats: true }, first: $first, orderBy: priority, orderMode: desc) {
      edges {
        node {
          id
          attack_pattern_id
          x_mitre_id
          attack_pattern_name
          level
          threats_count
          recommended_action
        }
      }
    }
  }
`;

const Content = ({ queryRef }: { queryRef: PreloadedQuery<WidgetDefenseTopGapsQuery> }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { defenseGaps } = usePreloadedQuery(widgetDefenseTopGapsQuery, queryRef);
  const gaps = (defenseGaps?.edges ?? []).map(({ node }) => node);
  if (gaps.length === 0) {
    return <WidgetNoData message={t_i18n('No uncovered technique is used by the known threats.')} />;
  }
  return (
    <List dense disablePadding data-testid="widget-defense-top-gaps">
      {gaps.map((gap) => (
        <ListItem key={gap.id} divider disableGutters sx={{ gap: 1 }}>
          <ListItemText
            primary={(
              <Link to={`/dashboard/techniques/attack_patterns/${gap.attack_pattern_id}`}>
                {gap.x_mitre_id ? `[${gap.x_mitre_id}] ${gap.attack_pattern_name}` : gap.attack_pattern_name}
              </Link>
            )}
            secondary={t_i18n('{count, plural, one {Used by # threat} other {Used by # threats}} - {action}', {
              values: { count: gap.threats_count, action: t_i18n(DEFENSE_ACTION_LABELS[gap.recommended_action as DefenseAction]) },
            })}
          />
          <Box sx={{ flexShrink: 0 }}>
            <Chip label={defenseLevelLabel(t_i18n, gap.level)} color={defenseLevelColor(theme, gap.level)} />
          </Box>
        </ListItem>
      ))}
    </List>
  );
};

interface WidgetDefenseTopGapsProps {
  title?: string | null;
  popover?: ReactNode;
}

const Loading = () => {
  const queryRef = useQueryLoading<WidgetDefenseTopGapsQuery>(widgetDefenseTopGapsQuery, { first: TOP_GAPS, levels: DEFENSE_UNCOVERED_LEVELS });
  return (
    <Box sx={{ height: '100%', overflow: 'auto' }}>
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <Content queryRef={queryRef} />
        </Suspense>
      ) : <Loader variant={LoaderVariant.inElement} />}
    </Box>
  );
};

const WidgetDefenseTopGaps = ({ title, popover }: WidgetDefenseTopGapsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <DefenseWidgetContainer title={title || t_i18n('Top uncovered techniques used by threats')} popover={popover}>
      <Loading />
    </DefenseWidgetContainer>
  );
};

export default WidgetDefenseTopGaps;
