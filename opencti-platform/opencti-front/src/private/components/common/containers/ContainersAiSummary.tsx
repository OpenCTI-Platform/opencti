import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import StixCoreObjectContainersHorizontalBar from '@components/common/containers/StixCoreObjectContainersHorizontalBar';
import { ContainersAiSummaryQuery } from './__generated__/ContainersAiSummaryQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import FilterIconButton from '../../../../components/FilterIconButton';

const containersAiSummaryQuery = graphql`
  query ContainersAiSummaryQuery(
    $first: Int
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    containersAiSummary(
      first: $first
      orderBy: $orderBy,
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      report
      topics
    }
  }
`;

interface ContainersAiSummaryComponentProps {
  stixCoreObjectId?: string;
  queryRef: PreloadedQuery<ContainersAiSummaryQuery>
  filters: FilterGroup
}

const ContainersAiSummaryComponent = ({ queryRef, filters, stixCoreObjectId }: ContainersAiSummaryComponentProps) => {
  const { t_i18n } = useFormatter();
  const { containersAiSummary } = usePreloadedQuery(
    containersAiSummaryQuery,
    queryRef,
  );
  if (containersAiSummary && containersAiSummary.report) {
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          style={{ marginBottom: 20 }}
        >
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Filters')}
            </Typography>
            <FilterIconButton
              filters={filters}
              styleNumber={2}
              redirection={true}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >{t_i18n('Limit')}</Typography>
            10
          </Grid>
          {stixCoreObjectId && (
            <Grid item={true} xs={6}>
              <StixCoreObjectContainersHorizontalBar stixCoreObjectId={stixCoreObjectId} />
            </Grid>
          )}
        </Grid>
        <MarkdownDisplay
          content={containersAiSummary.report}
          remarkGfmPlugin={true}
          commonmark={true}
          removeLinks={false}
        />
      </>
    );
  }
  return <WidgetNoData />;
};

interface ContainersAiSummaryProps {
  stixCoreObjectId?: string;
  first: number
  filters: FilterGroup
}

const ContainersAiSummary = ({ stixCoreObjectId, first, filters }: ContainersAiSummaryProps) => {
  const queryRef = useQueryLoading<ContainersAiSummaryQuery>(
    containersAiSummaryQuery,
    {
      first,
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore Excepts readonly array as variables but have simple array.
      filters,
      orderBy: 'created',
      orderMode: 'desc',
    },
  );
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ContainersAiSummaryComponent stixCoreObjectId={stixCoreObjectId} queryRef={queryRef} filters={filters}/>
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </>
  );
};

export default ContainersAiSummary;
