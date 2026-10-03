import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Typography } from '@mui/material';
import WidgetContainer from '../../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { DefenseLevelsBar } from '../DefenseLevelsBar';
import { DEFENSE_COVERED_LEVEL, DEFENSE_LEVEL_LABELS, DEFENSE_LEVEL_VALIDATED, DEFENSE_LEVELS, defenseLevelColor } from '../defenseMatrix-utils';
import { WidgetDefenseLevelsQuery } from './__generated__/WidgetDefenseLevelsQuery.graphql';

// Levels computed for the reader, from the evidences they can access
const widgetDefenseLevelsQuery = graphql`
  query WidgetDefenseLevelsQuery {
    defenseMatrix(threatScope: { mode: NONE }) {
      techniques_count
      levels
    }
  }
`;

const countFrom = (levels: ReadonlyArray<number>, minimum: number) => levels.reduce((sum, count, level) => (level >= minimum ? sum + count : sum), 0);

const Figure = ({ value, label, testId }: { value: number; label: string; testId: string }) => (
  <Box sx={{ flex: 1, minWidth: 0 }}>
    <Typography variant="h3" component="div" data-testid={testId}>{value}</Typography>
    <Typography variant="body2" color="text.secondary">{label}</Typography>
  </Box>
);

const Content = ({ queryRef }: { queryRef: PreloadedQuery<WidgetDefenseLevelsQuery> }) => {
  const { t_i18n } = useFormatter();
  const { defenseMatrix } = usePreloadedQuery(widgetDefenseLevelsQuery, queryRef);
  if (!defenseMatrix || defenseMatrix.techniques_count === 0) {
    return <WidgetNoData />;
  }
  const { levels } = defenseMatrix;
  return (
    <Box data-testid="widget-defense-levels" sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Figure value={countFrom(levels, DEFENSE_COVERED_LEVEL)} label={t_i18n('Techniques with a deployed detection')} testId="widget-defense-levels-covered" />
        <Figure value={countFrom(levels, DEFENSE_LEVEL_VALIDATED)} label={t_i18n('Techniques validated with OpenAEV')} testId="widget-defense-levels-validated" />
      </Box>
      <DefenseLevelsBar levels={levels} />
      <Box component="ul" aria-label={t_i18n('Defense levels')} sx={{ margin: 0, padding: 0, listStyle: 'none' }}>
        {DEFENSE_LEVELS.map((level) => (
          <Box component="li" key={level} sx={{ display: 'flex', alignItems: 'center', gap: 1, paddingBlock: 0.25 }}>
            <Box sx={{ width: 12, height: 12, borderRadius: '2px', flexShrink: 0, backgroundColor: defenseLevelColor(level), opacity: level === 0 ? 0.45 : 1 }} />
            <Typography variant="body2" sx={{ flex: 1 }}>{`${level} - ${t_i18n(DEFENSE_LEVEL_LABELS[level])}`}</Typography>
            <Typography variant="body2" data-testid={`widget-defense-levels-count-${level}`}>{levels[level] ?? 0}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
};

interface WidgetDefenseLevelsProps {
  title?: string | null;
  popover?: ReactNode;
}

const WidgetDefenseLevels = ({ title, popover }: WidgetDefenseLevelsProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<WidgetDefenseLevelsQuery>(widgetDefenseLevelsQuery, {});
  return (
    <WidgetContainer title={title || t_i18n('Techniques by defense level')} action={popover}>
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

export default WidgetDefenseLevels;
