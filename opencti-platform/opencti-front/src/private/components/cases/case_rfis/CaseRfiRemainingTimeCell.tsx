import { Box, Typography } from '@mui/material';
import React, { FunctionComponent } from 'react';
import type { CaseRfiSlaRemainingTimeSnapshot } from '@components/nav/slaExpiry/caseRfiSlaMetricsUtils';
import {
  formatCaseRfiSlaDurationDisplay,
  getCaseRfiSlaMetricsAt,
  getCaseRfiSlaProgress,
} from '@components/nav/slaExpiry/caseRfiSlaMetricsUtils';

const PROGRESS_FILL_COLOR = '#8628F8';
const PROGRESS_TRACK_COLOR = '#EDE4F7';

interface CaseRfiRemainingTimeCellProps {
  snapshot: CaseRfiSlaRemainingTimeSnapshot;
  nowMs: number;
}

const CaseRfiRemainingTimeCell: FunctionComponent<CaseRfiRemainingTimeCellProps> = ({
  snapshot,
  nowMs,
}) => {
  const progress = getCaseRfiSlaProgress(snapshot, nowMs);
  const { remainingTimeMs } = getCaseRfiSlaMetricsAt(snapshot, nowMs);
  const remainingLabel = formatCaseRfiSlaDurationDisplay(remainingTimeMs);

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        width: '100%',
        minWidth: 0,
        direction: 'rtl',
      }}
    >
      <Box
        sx={{
          flex: 1,
          minWidth: 0,
          height: 8,
          borderRadius: 999,
          backgroundColor: PROGRESS_TRACK_COLOR,
          overflow: 'hidden',
        }}
      >
        <Box
          sx={{
            width: `${progress * 100}%`,
            height: '100%',
            borderRadius: 999,
            backgroundColor: PROGRESS_FILL_COLOR,
            transition: 'width 0.35s ease',
          }}
        />
      </Box>
      <Typography
        component="span"
        dir="ltr"
        sx={{
          flexShrink: 0,
          fontSize: '0.8125rem',
          fontWeight: 500,
          color: 'text.primary',
          fontVariantNumeric: 'tabular-nums',
          whiteSpace: 'nowrap',
        }}
      >
        {remainingLabel}
      </Typography>
    </Box>
  );
};

export default CaseRfiRemainingTimeCell;
