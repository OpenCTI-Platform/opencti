import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Typography from '@mui/material/Typography';
import StixCoreObjectOpinionsList, { stixCoreObjectOpinionsListQuery } from '@components/analyses/opinions/StixCoreObjectOpinionsList';
import StixCoreObjectOpinionsRadarDialog from '@components/analyses/opinions/StixCoreObjectOpinionsRadarDialog';
import StixCoreObjectOpinionsRadar, { stixCoreObjectOpinionsRadarDistributionQuery } from './StixCoreObjectOpinionsRadar';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import {
  StixCoreObjectOpinionsRadarDistributionQuery,
  StixCoreObjectOpinionsRadarDistributionQuery$variables,
} from './__generated__/StixCoreObjectOpinionsRadarDistributionQuery.graphql';
import { StixCoreObjectOpinionsListQuery, StixCoreObjectOpinionsListQuery$variables } from './__generated__/StixCoreObjectOpinionsListQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixCoreObjectOpinionsOpenVocabQuery } from './__generated__/StixCoreObjectOpinionsOpenVocabQuery.graphql';

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
  const [open, setOpen] = useState(false);
  const [deleteActionTrigger, setDeleteActionTrigger] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleDelete = () => {
    setDeleteActionTrigger((prev) => !prev);
  };
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

  const variablesDistribution: StixCoreObjectOpinionsRadarDistributionQuery$variables = {
    objectId: stixCoreObjectId,
    field: 'opinion',
    operation: 'count',
    limit: 8,
  };
  const [distributionQueryRef, fetchLoadDistributionQuery] = useQueryLoader<StixCoreObjectOpinionsRadarDistributionQuery>(
    stixCoreObjectOpinionsRadarDistributionQuery,
  );
  const variablesList: StixCoreObjectOpinionsListQuery$variables = {
    first: 100,
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['objects'],
          values: [stixCoreObjectId],
        },
      ],
      filterGroups: [],
    },
  };
  const [listQueryRef, fetchLoadListQuery] = useQueryLoader<StixCoreObjectOpinionsListQuery>(
    stixCoreObjectOpinionsListQuery,
  );
  const fetchDistributionQuery = useCallback(
    () => {
      fetchLoadDistributionQuery(variablesDistribution, { fetchPolicy: 'network-only' });
      fetchLoadListQuery(variablesList, { fetchPolicy: 'network-only' });
    },
    [],
  );
  useEffect(
    () => {
      fetchLoadDistributionQuery(variablesDistribution, { fetchPolicy: 'store-and-network' });
      fetchLoadListQuery(variablesList, { fetchPolicy: 'store-and-network' });
    },
    [deleteActionTrigger],
  );
  const height = 180;
  return (
    <>
      <Typography
        variant={'h3'}
        gutterBottom={true}
        style={{ display: 'flex', marginTop: 20 }}
      >
        {t_i18n('Distribution of opinions')}
        <StixCoreObjectOpinionsRadarDialog
          stixCoreObjectId={stixCoreObjectId}
          opinionOptions={opinionOptions}
          fetchDistributionQuery={fetchDistributionQuery}
        />
      </Typography>
      {listQueryRef && (
        <React.Suspense fallback={<span />}>
          <StixCoreObjectOpinionsList
            queryRef={listQueryRef}
            handleClose={handleClose}
            open={open}
            onDelete={handleDelete}
          />
        </React.Suspense>
      )}
      <div style={{ height, cursor: 'pointer' }}>
        {distributionQueryRef && (
          <React.Suspense
            fallback={
              <div style={{ height }}>
                <Loader variant={LoaderVariant.inElement} />
              </div>
            }
          >
            <StixCoreObjectOpinionsRadar
              queryRef={distributionQueryRef}
              height={height}
              opinionOptions={opinionOptions}
              handleOpen={handleOpen}
            />
          </React.Suspense>
        )}
      </div>
    </>
  );
};

const StixCoreObjectOpinions: FunctionComponent<Omit<StixCoreObjectOpinionsProps, 'queryVocabulariesRef'>> = (
  props,
) => {
  const { typeToCategory } = useVocabularyCategory();
  const queryRef = useQueryLoading<StixCoreObjectOpinionsOpenVocabQuery>(stixCoreObjectOpinionsOpenVocabQuery, {
    category: typeToCategory('opinion-ov'),
  });
  return <div style={{ minHeight: '240px' }}>
    {queryRef && (
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
        <StixCoreObjectOpinionsComponent {...props} queryVocabulariesRef={queryRef}/>
      </React.Suspense>)
    }
  </div>;
};

export default StixCoreObjectOpinions;
