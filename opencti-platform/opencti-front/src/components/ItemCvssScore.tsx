import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from './common/tag/Tag';

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
};

const ItemCvssScore = ({ score }: ItemCvssScoreProps) => {
const ItemCvssScore = ({ score }: ItemCvssScoreProps) => {
  const theme = useTheme<Theme>();

  const getColorFromCVSS3Score = (cvssScore: number) => {
    switch (true) {
      case cvssScore === 0: return theme.palette.severity.default;
      case cvssScore <= 3: return theme.palette.severity.low;
      case cvssScore <= 5: return theme.palette.severity.info;
      case cvssScore <= 7: return theme.palette.severity.high;
      case cvssScore <= 9: return theme.palette.severity.critical;
      case cvssScore <= 10: return theme.palette.common.black;
      default: return theme.palette.severity.default;
    }
  };

  if (score === null || score === undefined) return '-';

  return (
    <Tag
      label={`${score}`}
      color={getColorFromCVSS3Score(score)}
    />
  );
};

export default ItemCvssScore;
