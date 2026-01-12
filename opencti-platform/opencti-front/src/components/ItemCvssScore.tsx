import Chip from '@mui/material/Chip';
import React, { CSSProperties } from 'react';
import { alpha, useTheme } from '@mui/material';
import type { Theme } from './Theme';

type ItemCvssScoreProps = {
  score?: number | null;
  style?: CSSProperties;
};

const ItemCvssScore = ({ score, style }: ItemCvssScoreProps) => {
  const theme = useTheme<Theme>();
  const inlineStyles = {
    whiteDark: {
      backgroundColor: '#ffffff',
      color: '#2b2b2b',
    },
    whiteLight: {
      backgroundColor: '#ffffff',
      color: '#2b2b2b',
      border: '1px solid #2b2b2b',
    },
    blueGrey: {
      backgroundColor: 'rgba(96, 125, 139, 0.08)',
      color: '#607d8b',
      borderColor: '#607d8b',
      fontStyle: 'italic',
    },
    green: {
      backgroundColor: alpha(theme.palette.success.main || '#17AB1F', 0.08),
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: 'rgba(92, 123, 245, 0.08)',
      color: '#5c7bf5',
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main || '#F14337', 0.08),
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: 'rgba(255, 152, 0, 0.08)',
      color: '#ff9800',
    },
    black: {
      backgroundColor: '#000000',
      color: '#ffffff',
    },
  };

  const getChipStyleFromCVSS3Score = (cvssScore: number) => {
    switch (true) {
      case cvssScore === 0: return inlineStyles.blueGrey;
      case cvssScore <= 3: return inlineStyles.green;
      case cvssScore <= 5: return inlineStyles.blue;
      case cvssScore <= 7: return inlineStyles.orange;
      case cvssScore <= 9: return inlineStyles.red;
      case cvssScore <= 10: return inlineStyles.black;
      default: return theme.palette.mode === 'light'
        ? inlineStyles.whiteLight
        : inlineStyles.whiteDark;
    }
  };

  if (score === null || score === undefined) return '-';

  return (
    <Chip
      style={{
        ...style,
        fontSize: 18,
        lineHeight: '18px',
        height: 38,
        textTransform: 'uppercase',
        borderRadius: 4,
        ...getChipStyleFromCVSS3Score(score),
      }}
      label={score}
    />
  );
};

export default ItemCvssScore;
