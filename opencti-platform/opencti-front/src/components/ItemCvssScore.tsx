import Chip from '@mui/material/Chip';
import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

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
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
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

type ItemCvssScoreProps = {
  score?: number | null;
  style?: CSSProperties
};

const ItemCvssScore = ({ score, style }: ItemCvssScoreProps) => {
  const theme = useTheme<Theme>();

  const getChipStyleFromCVSS3Score = (cvssScore: number) => {
    switch (true) {
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
        fontSize: 12,
        lineHeight: '12px',
        height: 25,
        textTransform: 'uppercase',
        borderRadius: 4,
        ...getChipStyleFromCVSS3Score(score),
      }}
      label={score}
    />
  );
};

export default ItemCvssScore;
