import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import Chart from '../charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import { itemColor } from '../../../../utils/Colors';
import { buildFiltersAndOptionsForWidgets, GqlFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import {
  StixCoreObjectsMultiHorizontalBarsDistributionQuery,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectsMultiHorizontalBarsDistributionQuery.graphql';
import { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { ReactNode, Suspense } from 'react';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { ApexOptions } from 'apexcharts';

const stixCoreObjectsMultiHorizontalBarsDistributionQuery = graphql`
  query StixCoreObjectsMultiHorizontalBarsDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $types: [String]
    $filters: FilterGroup
    $search: String
    $subDistributionRelationshipType: [String]
    $subDistributionToTypes: [String]
    $subDistributionField: String!
    $subDistributionStartDate: DateTime
    $subDistributionEndDate: DateTime
    $subDistributionDateAttribute: String
    $subDistributionOperation: StatsOperation!
    $subDistributionLimit: Int
    $subDistributionOrder: String
    $subDistributionTypes: [String]
    $subDistributionFilters: FilterGroup
    $subDistributionSearch: String
  ) {
    stixCoreObjectsDistribution(
      objectId: $objectId
      relationship_type: $relationship_type
      toTypes: $toTypes
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      types: $types
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
          id
        }
        ... on BasicRelationship {
          entity_type
          id
        }
        ... on StixCoreObject {
          stixCoreObjectsDistribution(
            relationship_type: $subDistributionRelationshipType
            toTypes: $subDistributionToTypes
            field: $subDistributionField
            startDate: $subDistributionStartDate
            endDate: $subDistributionEndDate
            dateAttribute: $subDistributionDateAttribute
            operation: $subDistributionOperation
            limit: $subDistributionLimit
            order: $subDistributionOrder
            types: $subDistributionTypes
            filters: $subDistributionFilters
            search: $subDistributionSearch
          ) {
            label
            value
            entity {
              ... on BasicObject {
                entity_type
                id
              }
              ... on AttackPattern {
                name
                description
              }
              ... on Campaign {
                name
                description
              }
              ... on CourseOfAction {
                name
                description
              }
              ... on Individual {
                name
                description
              }
              ... on Organization {
                name
                description
              }
              ... on Sector {
                name
                description
              }
              ... on System {
                name
                description
              }
              ... on Indicator {
                name
                description
              }
              ... on Infrastructure {
                name
                description
              }
              ... on IntrusionSet {
                name
                description
              }
              ... on Position {
                name
                description
              }
              ... on City {
                name
                description
              }
              ... on Country {
                name
                description
              }
              ... on Region {
                name
                description
              }
              ... on Malware {
                name
                description
              }
              ... on MalwareAnalysis {
                result_name
              }
              ... on ThreatActor {
                name
                description
              }
              ... on Tool {
                name
                description
              }
              ... on Vulnerability {
                name
                description
              }
              ... on Incident {
                name
                description
              }
              ... on Event {
                name
                description
              }
              ... on Channel {
                name
                description
              }
              ... on Narrative {
                name
                description
              }
              ... on Language {
                name
              }
              ... on DataComponent {
                name
                description
              }
              ... on DataSource {
                name
                description
              }
              ... on Case {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
              }
              ... on MarkingDefinition {
                definition_type
                definition
              }
              ... on Report {
                name
              }
              ... on Grouping {
                name
              }
              ... on Note {
                attribute_abstract
                content
              }
              ... on Opinion {
                opinion
              }
              ... on Label {
                value
              }
              ... on Status {
                template {
                  name
                  color
                }
              }
            }
          }
        }
        ... on AttackPattern {
          name
          description
        }
        ... on Campaign {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on AdministrativeArea {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
          description
        }
        ... on Tool {
          name
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
        }
        ... on Event {
          name
          description
        }
        ... on Channel {
          name
          description
        }
        ... on Narrative {
          name
          description
        }
        ... on Language {
          name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on Case {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
        ... on MarkingDefinition {
          definition_type
          definition
          x_opencti_color
        }
        ... on Creator {
          name
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
        }
        ... on Label {
          value
          color
        }
        ... on Status {
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface StixCoreObjectsMultiHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiHorizontalBarsDistributionQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    distributed?: boolean;
  };
}

const StixCoreObjectsMultiHorizontalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
}: StixCoreObjectsMultiHorizontalBarsComponentProps) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { stixCoreObjectsDistribution } = usePreloadedQuery(
    stixCoreObjectsMultiHorizontalBarsDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const data = stixCoreObjectsDistribution ?? [];

  if (data.length === 0) {
    return <WidgetNoData />;
  }

  const chartData = (data ?? [])
    .filter((n): n is NonNullable<typeof n> => n != null)
    .map((n) => {
      let color = isFieldForIdentifier(selection.attribute ?? '')
        ? itemColor(n.entity?.entity_type)
        : itemColor(n.label);

      if (n.entity?.color) {
        color = theme.palette.mode === 'light' && n.entity.color === '#ffffff'
          ? '#000000'
          : n.entity.color;
      }

      if (n.entity?.x_opencti_color) {
        color = theme.palette.mode === 'light' && n.entity.x_opencti_color === '#ffffff'
          ? '#000000'
          : n.entity.x_opencti_color;
      }

      if (n.entity?.template?.color) {
        color = theme.palette.mode === 'light' && n.entity.template.color === '#ffffff'
          ? '#000000'
          : n.entity.template.color;
      }

      return {
        x:
        selection.attribute?.endsWith('_id')
          ? getMainRepresentative(n.entity, t_i18n('Restricted'))
          : selection.attribute === 'entity_type'
            ? t_i18n(`entity_${n.label}`)
            : n.label,
        y: n.value,
        fillColor: color,
      };
    });

  return (
    <Chart
      options={horizontalBarsChartOptions(
        theme,
        true,
        simpleNumberFormat,
        undefined,
        parameters.distributed,
        navigate,
        undefined,
      ) as ApexOptions}
      series={[
        {
          name: selection.label ?? t_i18n('Number of entities'),
          data: chartData,
        },
      ]}
      type="bar"
      width="100%"
      height="100%"
    />
  );
};

interface StixCoreObjectsMultiHorizontalBarsProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: {
    title?: string;
    distributed?: boolean;
  };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsMultiHorizontalBarsDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const subSelection = resolvedDataSelection[1];

  const { startDate, endDate } = computeStartEndDates(config);

  const dateAttribute = selection.date_attribute?.length
    ? selection.date_attribute
    : 'created_at';

  const subDateAttribute = subSelection?.date_attribute?.length
    ? subSelection.date_attribute
    : 'created_at';

  const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, {
    startDate,
    endDate,
    dateAttribute,
  });

  const { filters: subFilters } = buildFiltersAndOptionsForWidgets(
    subSelection?.filters,
    {
      startDate,
      endDate,
      dateAttribute: subDateAttribute,
    },
  );

  return {
    types: DATA_SELECTION_TYPES,
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    filters: filters as unknown as GqlFilterGroup,
    limit: selection.number ?? 10,
    subDistributionField: subSelection?.attribute ?? 'entity_type',
    subDistributionOperation: 'count',
    subDistributionStartDate: startDate,
    subDistributionEndDate: endDate,
    subDistributionDateAttribute: subDateAttribute,
    subDistributionTypes: DATA_SELECTION_TYPES,
    subDistributionFilters: subFilters as unknown as GqlFilterGroup,
    subDistributionLimit: subSelection?.number ?? 10,
  };
};

const stixCoreObjectsMultiHorizontalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsMultiHorizontalBarsProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiHorizontalBarsDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiHorizontalBarsDistributionQuery,
    config,
    buildQueryVariables,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreObjectsMultiHorizontalBarsComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
          />
        </Suspense>
      )}
    </WidgetContainer>
  );
};

export default stixCoreObjectsMultiHorizontalBars;
