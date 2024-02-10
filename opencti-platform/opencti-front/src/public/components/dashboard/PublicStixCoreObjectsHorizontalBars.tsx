import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useTheme } from '@mui/styles';
import type { PublicManifestWidget } from './PublicManifest';
import { useFormatter } from '../../../components/i18n';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import { itemColor } from '../../../utils/Colors';
import { defaultValue } from '../../../utils/Graph';
import WidgetHorizontalBars from '../../../components/dashboard/WidgetHorizontalBars';
import type { Theme } from '../../../components/Theme';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsHorizontalBarsQuery } from './__generated__/PublicStixCoreObjectsHorizontalBarsQuery.graphql';

const publicStixCoreObjectsHorizontalBarsQuery = graphql`
  query PublicStixCoreObjectsHorizontalBarsQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsDistribution(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
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

interface PublicStixCoreObjectsHorizontalBarsComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsHorizontalBarsQuery>
}

const PublicStixCoreObjectsHorizontalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsHorizontalBarsComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsDistribution } = usePreloadedQuery(
    publicStixCoreObjectsHorizontalBarsQuery,
    queryRef,
  );

  if (
    publicStixCoreObjectsDistribution
    && publicStixCoreObjectsDistribution.length > 0
  ) {
    const selection = dataSelection[0];
    const data = publicStixCoreObjectsDistribution.map((n) => {
      let color = selection.attribute?.endsWith('_id')
        ? itemColor(n?.entity?.entity_type)
        : itemColor(n?.label);
      if (n?.entity?.color) {
        color = theme.palette.mode === 'light' && n.entity.color === '#ffffff'
          ? '#000000'
          : n.entity.color;
      }
      if (n?.entity?.x_opencti_color) {
        color = theme.palette.mode === 'light'
        && n.entity.x_opencti_color === '#ffffff'
          ? '#000000'
          : n.entity.x_opencti_color;
      }
      if (n?.entity?.template?.color) {
        color = theme.palette.mode === 'light'
        && n.entity.template.color === '#ffffff'
          ? '#000000'
          : n.entity.template.color;
      }
      return {
        // eslint-disable-next-line no-nested-ternary
        x: selection.attribute?.endsWith('_id')
          ? defaultValue(n?.entity)
          : selection.attribute === 'entity_type'
            ? t_i18n(`entity_${n?.label}`)
            : n?.label,
        y: n?.value,
        fillColor: color,
      };
    });
    const chartData = [
      {
        name: selection.label || t_i18n('Number of relationships'),
        data,
      },
    ];
    const redirectionUtils = selection.attribute === 'name'
      ? publicStixCoreObjectsDistribution.flatMap((n) => {
        if (!n || !n.entity) return [];
        return {
          id: n.entity.id,
          entity_type: n.entity.entity_type,
        };
      })
      : undefined;

    return (
      <WidgetHorizontalBars
        series={chartData}
        distributed={parameters.distributed}
        withExport={false}
        readonly={true}
        redirectionUtils={redirectionUtils}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsHorizontalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsHorizontalBarsQuery>(
    publicStixCoreObjectsHorizontalBarsQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Distribution of entities')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixCoreObjectsHorizontalBarsComponent
            queryRef={queryRef}
            parameters={parameters}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsHorizontalBars;
