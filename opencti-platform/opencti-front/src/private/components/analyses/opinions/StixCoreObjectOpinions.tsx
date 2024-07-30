import React, { FunctionComponent, useCallback, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Typography from '@mui/material/Typography';
import StixCoreObjectOpinionsRadar, { stixCoreObjectOpinionsRadarDistributionQuery } from './StixCoreObjectOpinionsRadar';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import {
  StixCoreObjectOpinionsRadarDistributionQuery,
  StixCoreObjectOpinionsRadarDistributionQuery$variables,
} from './__generated__/StixCoreObjectOpinionsRadarDistributionQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixCoreObjectOpinionsOpenVocabQuery } from './__generated__/StixCoreObjectOpinionsOpenVocabQuery.graphql';
import StixCoreObjectOpinionsDialog from './StixCoreObjectOpinionsRadarDialog';

interface StixCoreObjectOpinionsProps {
  stixCoreObjectId: string
  queryVocabulariesRef: PreloadedQuery<StixCoreObjectOpinionsOpenVocabQuery>
}

const stixCoreObjectOpinionsOpenVocabQuery = graphql`
  query StixCoreObjectOpinionsOpenVocabQuery($category: VocabularyCategory!) {
    vocabularies(category: $category) {
      edges {
        node {
          id
          name
          description
          order
        }
      }
    }
  }
`;

const StixCoreObjectOpinionsComponent: FunctionComponent<StixCoreObjectOpinionsProps> = ({
  stixCoreObjectId,
  queryVocabulariesRef,
}) => {
  const { t_i18n } = useFormatter();

  const { vocabularies } = usePreloadedQuery<StixCoreObjectOpinionsOpenVocabQuery>(
    stixCoreObjectOpinionsOpenVocabQuery,
    queryVocabulariesRef,
  );
  const opinionOptions = vocabularies?.edges
    .map((edge) => edge.node)
    .sort((n1, n2) => {
      if (n1.order === n2.order) {
        return n1.name.localeCompare(n2.name);
      }
      return (n1.order ?? 0) - (n2.order ?? 0);
    })
    .map((node, idx) => ({
      label: node.name.toLowerCase(),
      value: idx + 1,
    })) ?? [];

  const variables: StixCoreObjectOpinionsRadarDistributionQuery$variables = {
    objectId: stixCoreObjectId,
    field: 'opinion',
    operation: 'count',
    limit: 8,
  };
  const [queryRef, fetchLoadQuery] = useQueryLoader<StixCoreObjectOpinionsRadarDistributionQuery>(
    stixCoreObjectOpinionsRadarDistributionQuery,
  );
  const fetchDistributionQuery = useCallback(
    () => fetchLoadQuery(variables, { fetchPolicy: 'network-only' }),
    [],
  );
  useEffect(
    () => fetchLoadQuery(variables, { fetchPolicy: 'store-and-network' }),
    [],
  );

  const height = 260;

  return (
    <div style={{ height, marginTop: 20 }}>
      <Typography
        variant={'h3'}
        gutterBottom={true}
        style={{ float: 'left' }}
      >
        <div style={{ display: 'flex' }}>
          {t_i18n('Distribution of opinions')}
          <StixCoreObjectOpinionsDialog
            stixCoreObjectId={stixCoreObjectId}
            opinionOptions={opinionOptions}
            fetchDistributionQuery={fetchDistributionQuery}
          />
        </div>
      </Typography>
      <div className="clearfix" />
      {queryRef && (
        <React.Suspense
          fallback={
            <div style={{ height }}>
              <Loader variant={LoaderVariant.inElement} />
            </div>
          }
        >
          <StixCoreObjectOpinionsRadar
            queryRef={queryRef}
            height={height}
            opinionOptions={opinionOptions}
          />
        </React.Suspense>
      )}
    </div>
  );
};

const StixCoreObjectOpinions: FunctionComponent<Omit<StixCoreObjectOpinionsProps, 'queryVocabulariesRef'>> = (
  props,
) => {
  const { typeToCategory } = useVocabularyCategory();
  const queryRef = useQueryLoading<StixCoreObjectOpinionsOpenVocabQuery>(stixCoreObjectOpinionsOpenVocabQuery, {
    category: typeToCategory('opinion-ov'),
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixCoreObjectOpinionsComponent {...props} queryVocabulariesRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixCoreObjectOpinions;
