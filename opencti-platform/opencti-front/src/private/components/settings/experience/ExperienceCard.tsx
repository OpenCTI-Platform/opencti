import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface ExperienceCardProps {
  icon: ReactNode;
  overline: string;
  title: string;
  accent: string;
  statusChip?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  testId?: string;
}

/**
 * Body headline used inside the Filigran Experience cards (marketing pitch
 * titles), sized to sit under the card's hero title.
 */
export const ExperienceHeadline = ({ children }: { children: ReactNode }) => (
  <Typography
    sx={{
      fontFamily: '"Geologica", sans-serif',
      fontWeight: 600,
      fontSize: 15,
      lineHeight: 1.4,
    }}
  >
    {children}
  </Typography>
);

/**
 * Shared shell for the Filigran Experience cards (Enterprise Edition, XTM Hub).
 * Kept visually aligned with the OpenAEV Filigran Experience screen: outlined
 * paper with a 135deg accent gradient wash, a framed 52px icon box, an accent
 * overline above the title, and a pinned footer hosting the card actions.
 */
const ExperienceCard = ({
  icon,
  overline,
  title,
  accent,
  statusChip,
  footer,
  children,
  testId,
}: ExperienceCardProps) => {
  const theme = useTheme<Theme>();
  const hairline = `1px solid ${alpha(theme.palette.text?.primary ?? '#ffffff', 0.08)}`;

  return (
    <Paper
      variant="outlined"
      data-testid={testId}
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        padding: 2,
        borderRadius: 1,
        background: `linear-gradient(135deg, ${alpha(accent, 0.08)}, transparent 60%)`,
      }}
    >
      <Box sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 2,
      }}
      >
        <Box sx={{
          width: 52,
          height: 52,
          borderRadius: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          color: accent,
          backgroundColor: alpha(accent, 0.12),
          border: `1px solid ${alpha(accent, 0.3)}`,
        }}
        >
          {icon}
        </Box>
        <Box sx={{
          minWidth: 0,
          flex: 1,
        }}
        >
          <Typography sx={{
            fontFamily: '"Geologica", sans-serif',
            fontWeight: 600,
            fontSize: 11,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: accent,
          }}
          >
            {overline}
          </Typography>
          <Typography
            variant="h1"
            sx={{
              margin: 0,
              textTransform: 'none',
              '&::first-letter': { textTransform: 'none' },
            }}
          >
            {title}
          </Typography>
        </Box>
        {statusChip && (
          <Box sx={{
            flexShrink: 0,
            alignSelf: 'flex-start',
          }}
          >
            {statusChip}
          </Box>
        )}
      </Box>

      <Box sx={{
        flexGrow: 1,
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
      }}
      >
        {children}
      </Box>

      {footer && (
        <Box sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          gap: 1,
          flexWrap: 'wrap',
          paddingTop: 2,
          borderTop: hairline,
        }}
        >
          {footer}
        </Box>
      )}
    </Paper>
  );
};

export default ExperienceCard;
