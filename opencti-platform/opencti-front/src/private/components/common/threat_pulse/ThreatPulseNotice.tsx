import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import type SvgIcon from '@mui/material/SvgIcon';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';

interface ThreatPulseNoticeProps {
  icon: typeof SvgIcon;
  message: string;
  testId: string;
  // The one step the reader can take, on the same line when the width allows it.
  action?: ReactNode;
  tone?: 'default' | 'error';
}

// A state with nothing to measure: one line with its icon and, when the reader can act, the one action.
const ThreatPulseNotice = ({ icon: NoticeIcon, message, testId, action, tone = 'default' }: ThreatPulseNoticeProps) => {
  const theme = useTheme();
  return (
    <Box data-testid={testId} sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', columnGap: 2, rowGap: 1.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, flex: '1 1 260px', minWidth: 0 }}>
        <NoticeIcon
          aria-hidden
          sx={{ fontSize: 18, marginTop: '1px', flexShrink: 0, color: tone === 'error' ? theme.palette.error.main : theme.palette.text.secondary }}
        />
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid={`${testId}-message`}>{message}</Text>
      </Box>
      {/* An action can render nothing for a reader without the capability: the empty slot then takes no room */}
      {action && <Box sx={{ display: 'flex', alignItems: 'center', flexShrink: 0, maxWidth: '100%', '&:empty': { display: 'none' } }}>{action}</Box>}
    </Box>
  );
};

export default ThreatPulseNotice;
