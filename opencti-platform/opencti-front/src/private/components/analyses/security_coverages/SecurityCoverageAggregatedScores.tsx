import React, { FunctionComponent, useMemo } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import SecurityCoverageScores from './SecurityCoverageScores';
import { buildAverageCoverageMap, CoverageRelationEdge } from './securityCoverageAggregation';

interface SecurityCoverageAggregatedScoresProps {
  edges: ReadonlyArray<CoverageRelationEdge>;
}

/**
 * Displays per-Attack-Pattern averaged coverage scores for a Security Coverage.
 *
 * When multiple SC Results cover the same Attack Pattern with different scores,
 * this component shows the averaged result per coverage_name for each AP.
 */
const SecurityCoverageAggregatedScores: FunctionComponent<SecurityCoverageAggregatedScoresProps> = ({ edges }) => {
  const { coverageMap, computeTimeMs } = useMemo(() => {
    const start = performance.now();
    const map = buildAverageCoverageMap(edges);
    const elapsed = performance.now() - start;
    return { coverageMap: map, computeTimeMs: elapsed };
  }, [edges]);

  if (coverageMap.size === 0) {
    return null;
  }

  return (
    <Box sx={{ mb: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <Chip
          size="small"
          label={`${edges.length} edges → ${coverageMap.size} AP | ${computeTimeMs.toFixed(1)}ms`}
          color={computeTimeMs < 50 ? 'success' : computeTimeMs < 200 ? 'warning' : 'error'}
          variant="outlined"
        />
      </Box>
      {Array.from(coverageMap.entries()).map(([id, averages]) => (
        <Box key={id} sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <Typography variant="body2" sx={{ minWidth: 200, flexShrink: 0 }}>
            {id}
          </Typography>
          <SecurityCoverageScores
            coverage_information={averages}
            variant="header"
          />
        </Box>
      ))}
    </Box>
  );
};

export default SecurityCoverageAggregatedScores;
