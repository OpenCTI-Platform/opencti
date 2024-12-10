import React from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { RelatedContainerNode } from '@components/common/containers/related_containers/RelatedContainers';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  RelatedContainersDetailsQuery,
  RelatedContainersDetailsQuery$variables,
} from '@components/common/containers/related_containers/__generated__/RelatedContainersDetailsQuery.graphql';
import RelatedContainersDetailsTable from '@components/common/containers/related_containers/RelatedContainersDetailsTable';
import { useFormatter } from '../../../../../components/i18n';
import ExpandableMarkdown from '../../../../../components/ExpandableMarkdown';
import ItemMarkings from '../../../../../components/ItemMarkings';
import WidgetHorizontalBars from '../../../../../components/dashboard/WidgetHorizontalBars';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import ItemAssignees from '../../../../../components/ItemAssignees';
import ItemStatus from '../../../../../components/ItemStatus';
import ItemEntityType from '../../../../../components/ItemEntityType';
import ItemCreators from '../../../../../components/ItemCreators';
import ItemAuthor from '../../../../../components/ItemAuthor';

export const relatedContainersDetailsQuery = graphql`
  query RelatedContainersDetailsQuery(
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
  queryRef: PreloadedQuery<RelatedContainersDetailsQuery>;
}> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<RelatedContainersDetailsQuery>(
    relatedContainersDetailsQuery,
    queryRef,
  );

  const series = data?.stixCoreObjectsDistribution?.map((objectDistribution) => ({
    name: t_i18n(`entity_${objectDistribution?.label}`),
    data: [objectDistribution?.value],
  })) as ApexAxisChartSeries;

  return (<div style={{ height: 150 }}><WidgetHorizontalBars
    series={series}
    distributed={false}
    stacked
    stackType='100%'
    legend={true}
                                       /></div>);
};

interface RelatedContainersDetailsProps {
  containerId: string;
  relatedContainer: RelatedContainerNode;
}

const RelatedContainersDetails: React.FC<RelatedContainersDetailsProps> = ({ containerId, relatedContainer }) => {
  const { t_i18n, fldt } = useFormatter();

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

  const queryRef = useQueryLoading<RelatedContainersDetailsQuery>(
    relatedContainersDetailsQuery,
    {
      field: 'entity_type',
      operation: 'count',
      filters: queryFilters,
    } as unknown as RelatedContainersDetailsQuery$variables,
  );

  return (
    <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
      <Grid item xs={6}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Entity Type')}
        </Typography>
        <ItemEntityType entityType={relatedContainer.entity_type} />

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 40 }}
        >
          {t_i18n('Description')}
        </Typography>
        <ExpandableMarkdown source={relatedContainer.description} limit={300} />

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Author')}
        </Typography>
        <ItemAuthor
          createdBy={relatedContainer.createdBy}
        />

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Modification date')}
        </Typography>
        {fldt(relatedContainer.modified)}
      </Grid>
      <Grid item xs={6}>

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Marking')}
        </Typography>
        <ItemMarkings markingDefinitions={relatedContainer.objectMarking}/>

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Processing status')}
        </Typography>
        <ItemStatus status={relatedContainer.status} disabled={!relatedContainer.workflowEnabled} />

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Assignees')}
        </Typography>
        <ItemAssignees assignees={relatedContainer.objectAssignee ?? []} stixDomainObjectId={relatedContainer.id}/>

        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Creators')}
        </Typography>
        <ItemCreators creators={relatedContainer.creators ?? []} />

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
      <RelatedContainersDetailsTable filters={queryFilters} />
    </Grid>
  );
};

export default RelatedContainersDetails;
