import React, { FunctionComponent, useCallback, useEffect } from 'react';
import { useQueryLoader } from 'react-relay';
import StixCoreObjectOpinionsRadar, { stixCoreObjectOpinionsRadarFragmentQuery } from './StixCoreObjectOpinionsRadar';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import {
  StixCoreObjectOpinionsRadarDistributionQuery, StixCoreObjectOpinionsRadarDistributionQuery$variables,
} from './__generated__/StixCoreObjectOpinionsRadarDistributionQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface StixCoreObjectOpinionsProps {
  stixCoreObjectId: string
  variant: string
  height: number
  marginTop: number
  refetch: () => void
}

const StixCoreObjectOpinions: FunctionComponent<StixCoreObjectOpinionsProps> = ({ stixCoreObjectId, variant, height, marginTop }) => {
  const { typeToCategory } = useVocabularyCategory();
  const variables: StixCoreObjectOpinionsRadarDistributionQuery$variables = {
    // Opininions distribution
    objectId: stixCoreObjectId,
    field: 'opinion',
    operation: 'count',
    limit: 8,
    // Vocabularies
    category: typeToCategory('opinion-ov'),
    // My opinion
    id: stixCoreObjectId,
  };
  const [queryRef, fetchLoadQuery] = useQueryLoader<StixCoreObjectOpinionsRadarDistributionQuery>(stixCoreObjectOpinionsRadarFragmentQuery);
  const fetchQuery = useCallback(() => fetchLoadQuery(variables, { fetchPolicy: 'network-only' }), []);
  useEffect(() => fetchLoadQuery(variables, { fetchPolicy: 'store-and-network' }), []);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixCoreObjectOpinionsRadar
        stixCoreObjectId={stixCoreObjectId}
        queryRef={queryRef}
        fetchQuery={fetchQuery}
        variant={variant}
        height={height}
        marginTop={marginTop}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};
export default StixCoreObjectOpinions;
