import React from 'react';
import { Box, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { DefenseLevelsBar } from './DefenseLevelsBar';
import { summarizeLevels, tacticDisplayName } from './defenseMatrix-utils';

export interface DefenseTacticCoverageData {
  readonly kill_chain_phase_id: string;
  readonly kill_chain_name: string;
  readonly phase_name: string;
  readonly techniques_count: number;
  readonly levels: ReadonlyArray<number>;
  readonly threat_techniques_count: number;
  readonly threat_levels: ReadonlyArray<number>;
}

interface DefenseTacticsCoverageProps {
  tactics: ReadonlyArray<DefenseTacticCoverageData>;
  // Restrict every tactic to the techniques used by the threats of the overlay
  threatsOnly?: boolean;
  killChainName?: string;
}

const DefenseTacticsCoverage = ({ tactics, threatsOnly = false, killChainName }: DefenseTacticsCoverageProps) => {
  const { t_i18n } = useFormatter();
  const rows = tactics
    .filter((tactic) => !killChainName || tactic.kill_chain_name === killChainName)
    .map((tactic) => {
      const levels = threatsOnly ? tactic.threat_levels : tactic.levels;
      return { tactic, levels, summary: summarizeLevels(levels) };
    })
    .filter((row) => row.summary.total > 0);
  if (rows.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        {threatsOnly ? t_i18n('No technique of the overlay threats is known.') : t_i18n('No technique is known.')}
      </Typography>
    );
  }
  return (
    <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="defense-tactics-coverage">
      {rows.map(({ tactic, levels, summary }) => (
        <Box
          component="li"
          key={tactic.kill_chain_phase_id}
          sx={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 1fr) 3fr 64px', alignItems: 'center', gap: 1.5, paddingBlock: 0.5 }}
        >
          <Typography variant="body2" noWrap title={tacticDisplayName(tactic.phase_name)}>{tacticDisplayName(tactic.phase_name)}</Typography>
          <DefenseLevelsBar
            levels={levels}
            label={t_i18n('{name}: {covered} of {total} techniques covered', {
              values: { name: tacticDisplayName(tactic.phase_name), covered: summary.covered, total: summary.total },
            })}
          />
          <Typography variant="body2" sx={{ textAlign: 'right', fontWeight: 600 }}>{`${summary.percent}%`}</Typography>
        </Box>
      ))}
    </Box>
  );
};

export default DefenseTacticsCoverage;
