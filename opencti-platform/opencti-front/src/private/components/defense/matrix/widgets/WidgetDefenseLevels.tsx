import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../components/Theme';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { DefenseLevelsBar } from '../DefenseLevelsBar';
import { DEFENSE_COVERED_LEVEL, DEFENSE_LEVEL_VALIDATED, DEFENSE_LEVELS, defenseLevelColor, defenseLevelLabel } from '../defenseMatrix-utils';
import { WidgetDefenseLevelsQuery } from './__generated__/WidgetDefenseLevelsQuery.graphql';
import DefenseWidgetContainer from './DefenseWidgetContainer';

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
  const theme = useTheme<Theme>();
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
            <Box sx={{ width: 12, height: 12, borderRadius: '2px', flexShrink: 0, backgroundColor: defenseLevelColor(theme, level) }} />
            <Typography variant="body2" sx={{ flex: 1 }}>{defenseLevelLabel(t_i18n, level)}</Typography>
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

const Loading = () => {
  const queryRef = useQueryLoading<WidgetDefenseLevelsQuery>(widgetDefenseLevelsQuery, {});
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

const WidgetDefenseLevels = ({ title, popover }: WidgetDefenseLevelsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <DefenseWidgetContainer title={title || t_i18n('Techniques by defense level')} popover={popover}>
      <Loading />
    </DefenseWidgetContainer>
  );
};

export default WidgetDefenseLevels;
