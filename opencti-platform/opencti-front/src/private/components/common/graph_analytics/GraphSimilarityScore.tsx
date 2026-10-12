import React from 'react';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { formatSimilarityScore, similarityScoreSeverity } from './graphAnalyticsUtils';

interface GraphSimilarityScoreProps {
  score: number;
  jaccard: number;
  structural: number;
}

/** "67% similar", with the two measures the score is built on in its tooltip. */
const GraphSimilarityScore = ({ score, jaccard, structural }: GraphSimilarityScoreProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} data-testid="graph-similarity-score">
          <Chip label={t_i18n('{score} similar', { values: { score: formatSimilarityScore(score) } })} severity={similarityScoreSeverity(score)} />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {t_i18n('Combines the weighted Jaccard similarity of the shared elements ({jaccard}) and the structural similarity of the relationships ({structural}).', {
          values: { jaccard: formatSimilarityScore(jaccard), structural: formatSimilarityScore(structural) },
        })}
      </TooltipContent>
    </Tooltip>
  );
};

export default GraphSimilarityScore;
