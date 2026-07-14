import React from 'react';
import { Box, Tooltip, Typography } from '@mui/material';
import SecurityCoverageScores from '../../../analyses/security_coverages/SecurityCoverageScores';
import MatrixEntityMarker from './MatrixEntityMarker';
import AttackPatternsMatrixShouldCoverIcon from './AttackPatternsMatrixShouldCoverIcon';
import { MatrixCellEntity } from './MatrixEntityMarkers';
import { useFormatter } from '../../../../../components/i18n';
import { capitalizeFirstLetter } from '../../../../../utils/String';

export type CoverageInformation = ReadonlyArray<{
  readonly coverage_name: string;
  readonly coverage_score: number;
}>;

interface MatrixCoverageIndicatorProps {
  coverageInformation: CoverageInformation;
  // Entities using this technique, listed alongside the coverage scores in the hover.
  entities?: MatrixCellEntity[];
  // "Compare with security posture" overlap indicator (green tick / red cross).
  // When set, it is pinned in the same top-right corner as the coverage donuts.
  showOverlap?: boolean;
  isOverlapping?: boolean;
}

// Compact detection/prevention coverage donuts pinned to the top-right corner of
// a technique cell, with a full description shown on hover that also lists the
// entities using the technique. When the "compare with security posture" mode is
// active, the overlap tick/cross is rendered in the same corner, next to the
// coverage donuts.
//
// The red -> green score scale is reserved for coverage only; entity "uses"
// markers use a separate (red/green-free) categorical palette, so the two
// encodings cannot be confused.
const MatrixCoverageIndicator = ({
  coverageInformation,
  entities = [],
  showOverlap = false,
  isOverlapping = false,
}: MatrixCoverageIndicatorProps) => {
  const { t_i18n } = useFormatter();

  const hasCoverage = coverageInformation && coverageInformation.length > 0;
  if (!hasCoverage && !showOverlap) {
    return null;
  }

  const description = (
    <Box sx={{ padding: 0.5 }}>
      <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', marginBottom: 0.5 }}>
        {t_i18n('Coverage scores')}
      </Typography>
      {coverageInformation.map((c) => (
        <Typography key={c.coverage_name} variant="caption" sx={{ display: 'block' }}>
          {`${capitalizeFirstLetter(c.coverage_name)}: ${c.coverage_score}/100`}
        </Typography>
      ))}
      {entities.length > 0 && (
        <>
          <Typography variant="caption" sx={{ fontWeight: 600, display: 'block', marginTop: 1, marginBottom: 0.5 }}>
            {t_i18n('Used by')}
          </Typography>
          {entities.map((entity) => (
            <Box key={entity.id} sx={{ display: 'flex', alignItems: 'center', gap: 0.75, marginBottom: 0.25 }}>
              <MatrixEntityMarker shape={entity.shape} color={entity.color} label={entity.name} />
              <Typography variant="caption">{entity.name}</Typography>
            </Box>
          ))}
        </>
      )}
    </Box>
  );

  return (
    <Box
      sx={{
        position: 'absolute',
        top: -10,
        right: -6,
        display: 'flex',
        alignItems: 'center',
        gap: 0.25,
        zIndex: 2,
        pointerEvents: 'auto',
      }}
    >
      {showOverlap && (
        <AttackPatternsMatrixShouldCoverIcon isOverlapping={isOverlapping} />
      )}
      {hasCoverage && (
        <Tooltip title={description} placement="top" arrow>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <SecurityCoverageScores coverage_information={coverageInformation} variant="matrix" />
          </Box>
        </Tooltip>
      )}
    </Box>
  );
};

export default MatrixCoverageIndicator;
