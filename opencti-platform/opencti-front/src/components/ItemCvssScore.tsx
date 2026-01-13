import Chip from '@mui/material/Chip';
import React, { CSSProperties } from 'react';
import { alpha } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

type ItemCvssScoreProps = {
  score?: number | null;
  style?: CSSProperties;
};

const ItemCvssScore = ({ score, style }: ItemCvssScoreProps) => {
  const theme = useTheme<Theme>();
  const inlineStyles = {
    whiteDark: {
      backgroundColor: theme.palette.common.white,
      color: '#313235',
    },
    whiteLight: {
      backgroundColor: theme.palette.common.white,
      color: '#313235',
      border: '1px solid #313235',
    },
    blueGrey: {
      backgroundColor: alpha(theme.palette.common.grey || '#95969D', 0.08),
      color: theme.palette.common.grey,
      borderColor: theme.palette.common.grey,
      fontStyle: 'italic',
    },
    green: {
      backgroundColor: alpha(theme.palette.success.main || '#17AB1F', 0.08),
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: alpha(theme.palette.severity?.info || '#4DCCFF', 0.08),
      color: theme.palette.severity?.info || '#4DCCFF',
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main || '#F14337', 0.08),
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity?.high || '#E6700F', 0.08),
      color: theme.palette.severity?.high || '#E6700F',
    },
    black: {
      backgroundColor: theme.palette.common.black,
      color: theme.palette.common.white,
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
