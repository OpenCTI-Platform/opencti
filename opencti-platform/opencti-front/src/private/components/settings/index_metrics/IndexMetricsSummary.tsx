import React from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Card from '@common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { IndexMetricsSummaryStatsQuery } from './__generated__/IndexMetricsSummaryStatsQuery.graphql';
import { Box, Grid2 as Grid, Typography } from '@mui/material';

interface IndexMetricsSummaryComponentProps {
  queryRef: PreloadedQuery<IndexMetricsSummaryStatsQuery>;
};

const indexMetricsSummaryStatsQuery = graphql`
  query IndexMetricsSummaryStatsQuery {
    elasticSearchMetrics {
      docs {
        count
        total_size_in_bytes
      }
    }
  }
`;
const IndexMetricsSummaryComponent = ({ queryRef }: IndexMetricsSummaryComponentProps) => {
  const { t_i18n, b } = useFormatter();
  const data = usePreloadedQuery(indexMetricsSummaryStatsQuery, queryRef);
  const toNumber = (value: unknown): number | null => {
    if (value == null) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const docsCount = toNumber(data.elasticSearchMetrics?.docs?.count);
  const clusterSize = toNumber(data.elasticSearchMetrics?.docs?.total_size_in_bytes);

  return (
    <Grid container>
      <Grid size={{ md: 2, xs: 6 }}>
        <Card sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography sx={{ paddingRight: 3 }} variant="body1">{t_i18n('Documents')}:</Typography>
            <Typography>{docsCount}</Typography>
          </Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography sx={{ paddingRight: 3 }} variant="body1">{t_i18n('Size')}: </Typography>
            <Typography>{b(clusterSize)}</Typography>
          </Box>
        </Card>
      </Grid>
    </Grid>

  );
};

const IndexMetricsSummary = () => {
  const queryRef = useQueryLoading<IndexMetricsSummaryStatsQuery>(indexMetricsSummaryStatsQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <IndexMetricsSummaryComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default IndexMetricsSummary;
