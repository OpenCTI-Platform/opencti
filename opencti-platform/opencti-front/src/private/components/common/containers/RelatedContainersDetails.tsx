import React, { useEffect } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { RelatedContainerNode } from '@components/common/containers/RelatedContainers';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import {
  RelatedContainersDetailsDistributionQuery,
  RelatedContainersDetailsDistributionQuery$variables,
} from '@components/common/containers/__generated__/RelatedContainersDetailsDistributionQuery.graphql';

import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemMarkings from '../../../../components/ItemMarkings';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';

export const relatedContainersDetailsDistributionQuery = graphql`
  query RelatedContainersDetailsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $filters: FilterGroup!
  ) {
    stixCoreObjectsDistribution(
      field: $field
      operation: $operation
      filters: $filters
    ) {
      label
      value
    }
  }
`;

const RelatedContainersDetailsDistribution: React.FC<{
  queryRef: PreloadedQuery<RelatedContainersDetailsDistributionQuery>;
}> = ({ queryRef }) => {
  const data = usePreloadedQuery<RelatedContainersDetailsDistributionQuery>(
    relatedContainersDetailsDistributionQuery,
    queryRef,
  );

  const series = data?.stixCoreObjectsDistribution?.map((objectDistribution) => ({
    name: objectDistribution?.label,
    data: [objectDistribution?.value],
  })) as ApexAxisChartSeries;

  return (<WidgetHorizontalBars
    series={series}
    distributed={false}
    stacked
    stackType='100%'
    legend={true}
          />);
};

interface RelatedContainersDetailsProps {
  containerId: string;
  relatedContainer: RelatedContainerNode;
}

export const RelatedContainersDetails: React.FC<RelatedContainersDetailsProps> = ({ containerId, relatedContainer }) => {
  const { t_i18n, fldt } = useFormatter();

  const [queryRef, loadQuery] = useQueryLoader<RelatedContainersDetailsDistributionQuery>(
    relatedContainersDetailsDistributionQuery,
  );

  // TODO can be reused for other queries
  const queryFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['Stix-Cyber-Observable', 'Indicator'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [
      {
        mode: 'and',
        filters: [
          {
            key: 'regardingOf',
            values: [
              { key: 'relationship_type', values: ['object'] },
              { key: 'id', values: [containerId] },
            ],
            operator: 'eq',
            mode: 'or',
          },
          {
            key: 'regardingOf',
            values: [
              { key: 'relationship_type', values: ['object'] },
              { key: 'id', values: [relatedContainer.id] },
            ],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      },
    ],
  };

  useEffect(() => {
    if (!queryRef) {
      loadQuery({
        field: 'entity_type',
        operation: 'count',
        filters: queryFilters,
      } as unknown as RelatedContainersDetailsDistributionQuery$variables);
    }
  }, [loadQuery]);

  return (
    <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
      <Grid item xs={6}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Description')}
        </Typography>
        <ExpandableMarkdown source={relatedContainer.description} limit={300} />
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Assignees')}
        </Typography>
        {/* <ItemAssignees assignees={relatedContainer.objectAssignee ?? []} stixDomainObjectId={relatedContainer.id}/> */}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Original creation date')}
        </Typography>
        {fldt(relatedContainer.created ?? relatedContainer.published)}
      </Grid>
      <Grid item xs={6}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Due Date')}
        </Typography>
        {/* <ItemDueDate due_date={relatedContainer.due_date} variant="inElement" /> */}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Processing status')}
        </Typography>
        {/* <ItemStatus status={relatedContainer.status} disabled={!relatedContainer.workflowEnabled} /> */}
        {relatedContainer.objectMarking && relatedContainer.objectMarking.length > 0 && (
        <>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Marking')}
          </Typography>
          <ItemMarkings markingDefinitions={relatedContainer.objectMarking}/>
        </>
        )}
      </Grid>
      <Grid item xs={12}>
        <Typography
          variant="h4"
          style={{ marginTop: 20 }}
        >
          {t_i18n('Correlated indicators and observables distribution')}
        </Typography>
        {queryRef && <RelatedContainersDetailsDistribution queryRef={queryRef} />}
      </Grid>
    </Grid>

  );
};
