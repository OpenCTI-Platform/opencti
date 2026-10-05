import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Typography } from '@mui/material';
import WidgetContainer from '../../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import DefenseTacticsCoverage from '../DefenseTacticsCoverage';
import { summarizeLevels } from '../defenseMatrix-utils';
import { WidgetDefenseTacticCoverageQuery } from './__generated__/WidgetDefenseTacticCoverageQuery.graphql';

const widgetDefenseTacticCoverageQuery = graphql`
  query WidgetDefenseTacticCoverageQuery {
    defenseMatrix(threatScope: { mode: ALL }) {
      threats_count
      threat_levels
      levels
      tactics {
        kill_chain_phase_id
        kill_chain_name
        phase_name
        x_opencti_order
        techniques_count
        levels
        threat_techniques_count
        threat_levels
      }
    }
  }
`;

const MITRE_ATTACK = 'mitre-attack';

const Content = ({ queryRef }: { queryRef: PreloadedQuery<WidgetDefenseTacticCoverageQuery> }) => {
  const { t_i18n } = useFormatter();
  const { defenseMatrix } = usePreloadedQuery(widgetDefenseTacticCoverageQuery, queryRef);
  if (!defenseMatrix || defenseMatrix.tactics.length === 0) {
    return <WidgetNoData />;
  }
  const threatsOnly = defenseMatrix.threats_count > 0;
  const summary = summarizeLevels(threatsOnly ? defenseMatrix.threat_levels : defenseMatrix.levels);
  const hasMitre = defenseMatrix.tactics.some((t) => t.kill_chain_name === MITRE_ATTACK);
  return (
    <Box data-testid="widget-defense-tactic-coverage">
      <Typography variant="body2" color="text.secondary" sx={{ marginBottom: 1 }}>
        {threatsOnly
          ? t_i18n('{percent}% of the techniques used by {threats} threats are covered', { values: { percent: summary.percent, threats: defenseMatrix.threats_count } })
          : t_i18n('{percent}% of the techniques are covered', { values: { percent: summary.percent } })}
      </Typography>
      <DefenseTacticsCoverage tactics={defenseMatrix.tactics} threatsOnly={threatsOnly} killChainName={hasMitre ? MITRE_ATTACK : undefined} />
    </Box>
  );
};

interface WidgetDefenseTacticCoverageProps {
  title?: string | null;
  popover?: ReactNode;
}

const WidgetDefenseTacticCoverage = ({ title, popover }: WidgetDefenseTacticCoverageProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<WidgetDefenseTacticCoverageQuery>(widgetDefenseTacticCoverageQuery, {});
  return (
    <WidgetContainer title={title || t_i18n('Defense coverage by tactic')} action={popover}>
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <Content queryRef={queryRef} />
        </Suspense>
      ) : <Loader variant={LoaderVariant.inElement} />}
    </WidgetContainer>
  );
};

export default WidgetDefenseTacticCoverage;
