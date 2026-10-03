import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, List, ListItem, ListItemText } from '@mui/material';
import { Chip } from '@filigran/design-system';
import WidgetContainer from '../../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { DEFENSE_ACTION_LABELS, DEFENSE_LEVEL_LABELS, type DefenseAction, defenseLevelColor } from '../defenseMatrix-utils';
import { WidgetDefenseTopGapsQuery } from './__generated__/WidgetDefenseTopGapsQuery.graphql';

const TOP_GAPS = 10;

const widgetDefenseTopGapsQuery = graphql`
  query WidgetDefenseTopGapsQuery($first: Int) {
    defenseGaps(threatScope: { mode: ALL }, filter: { onlyUsedByThreats: true }, first: $first, orderBy: priority, orderMode: desc) {
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
  const { defenseGaps } = usePreloadedQuery(widgetDefenseTopGapsQuery, queryRef);
  const gaps = (defenseGaps?.edges ?? []).map(({ node }) => node);
  if (gaps.length === 0) {
    return <WidgetNoData message={t_i18n('No uncovered technique is used by the known threats.')} />;
  }
  return (
    <List dense disablePadding data-testid="widget-defense-top-gaps">
      {gaps.map((gap) => (
        <ListItem key={gap.id} divider disableGutters secondaryAction={<Chip label={`${gap.level}`} color={defenseLevelColor(gap.level)} title={t_i18n(DEFENSE_LEVEL_LABELS[gap.level])} />}>
          <ListItemText
            primary={(
              <Link to={`/dashboard/techniques/attack_patterns/${gap.attack_pattern_id}`}>
                {gap.x_mitre_id ? `[${gap.x_mitre_id}] ${gap.attack_pattern_name}` : gap.attack_pattern_name}
              </Link>
            )}
            secondary={`${t_i18n('Used by {count} threats', { values: { count: gap.threats_count } })} - ${t_i18n(DEFENSE_ACTION_LABELS[gap.recommended_action as DefenseAction])}`}
          />
        </ListItem>
      ))}
    </List>
  );
};

interface WidgetDefenseTopGapsProps {
  title?: string | null;
  popover?: ReactNode;
}

const WidgetDefenseTopGaps = ({ title, popover }: WidgetDefenseTopGapsProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<WidgetDefenseTopGapsQuery>(widgetDefenseTopGapsQuery, { first: TOP_GAPS });
  return (
    <WidgetContainer title={title || t_i18n('Top uncovered techniques used by threats')} action={popover}>
      <Box sx={{ height: '100%', overflow: 'auto' }}>
        {queryRef ? (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <Content queryRef={queryRef} />
          </Suspense>
        ) : <Loader variant={LoaderVariant.inElement} />}
      </Box>
    </WidgetContainer>
  );
};

export default WidgetDefenseTopGaps;
