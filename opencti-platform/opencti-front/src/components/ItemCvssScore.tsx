import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from './common/tag/Tag';

type ItemCvssScoreProps = {
  score?: number | null;
};

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
