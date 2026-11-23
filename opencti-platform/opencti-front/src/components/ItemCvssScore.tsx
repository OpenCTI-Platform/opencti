import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';
import Tag from './common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { isEmptyField } from '../utils/utils';
import { cvssTone } from '../utils/severityTone';

type ItemCvssScoreProps = {
  score?: number | null;
};

const ItemCvssScore = ({ score }: ItemCvssScoreProps) => {
  const theme = useTheme<Theme>();

  if (isEmptyField(score)) return EMPTY_VALUE;

  const tone = cvssTone(score);
  return (
    <Tag
      label={`${score}`}
      {...(tone ? { severity: tone } : { color: theme.palette.common.black })}
    />
  );
};

export default ItemCvssScore;
