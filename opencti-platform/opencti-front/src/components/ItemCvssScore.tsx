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
      color: theme.palette.tertiary.grey[700],
    },
    whiteLight: {
      backgroundColor: theme.palette.common.white,
      color: theme.palette.tertiary.grey[700],
      border: `1px solid ${theme.palette.tertiary.grey[800]}`,
    },
    blueGrey: {
      backgroundColor: theme.palette.severity.default,
      color: theme.palette.severity.default,
      borderColor: theme.palette.severity.default,
      fontStyle: 'italic',
    },
    green: {
      backgroundColor: theme.palette.severity.low,
      color: theme.palette.severity.low,
    },
    blue: {
      backgroundColor: theme.palette.severity.info,
      color: theme.palette.severity.info,
    },
    red: {
      backgroundColor: theme.palette.severity.critical,
      color: theme.palette.severity.critical,
    },
    orange: {
      backgroundColor: theme.palette.severity.high,
      color: theme.palette.severity.high,
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
