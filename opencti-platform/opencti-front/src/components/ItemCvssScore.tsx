import Tag from './common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { isEmptyField } from '../utils/utils';
import { cvssTone } from '../utils/severityTone';

type ItemCvssScoreProps = {
  score?: number | null;
};

const ItemCvssScore = ({ score }: ItemCvssScoreProps) => {
  if (isEmptyField(score)) return EMPTY_VALUE;

  return <Tag label={`${score}`} severity={cvssTone(score)} />;
};

export default ItemCvssScore;
