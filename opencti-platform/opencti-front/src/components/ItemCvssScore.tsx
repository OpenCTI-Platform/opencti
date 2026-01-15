import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

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
      backgroundColor: theme.palette.common.grey,
      color: theme.palette.common.grey,
      borderColor: theme.palette.common.grey,
      fontStyle: 'italic',
    },
    green: {
      backgroundColor: theme.palette.success.main,
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: theme.palette.severity?.info,
      color: theme.palette.severity?.info,
    },
    red: {
      backgroundColor: theme.palette.error.main,
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: theme.palette.severity?.high,
      color: theme.palette.severity?.high,
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
    <Tag
      style={{
        ...style,
        fontSize: 18,
        lineHeight: '18px',
        height: 38,
        textTransform: 'uppercase',
        borderRadius: 4,
        ...getChipStyleFromCVSS3Score(score),
      }}
      label={`${score}`}
    />
  );
};

export default ItemCvssScore;
