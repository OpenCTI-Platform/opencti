import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import React from 'react';
import type { PublicManifestWidget } from './PublicManifest';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';
import { defaultValue } from '../../../utils/Graph';
import WidgetHorizontalBars from '../../../components/dashboard/WidgetHorizontalBars';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsHorizontalBarsQuery } from './__generated__/PublicStixRelationshipsHorizontalBarsQuery.graphql';

const publicStixRelationshipsHorizontalBarsQuery = graphql`
  query PublicStixRelationshipsHorizontalBarsQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationshipsDistribution(
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
        ... on Report {
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
        ... on KillChainPhase {
          kill_chain_name
          phase_name
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
      }
    }
  }
`;

interface PublicStixRelationshipsHorizontalBarsComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsHorizontalBarsQuery>
}

const PublicStixRelationshipsHorizontalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsHorizontalBarsComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsHorizontalBarsQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const selection = dataSelection[0];
    const finalField = selection.attribute || 'entity_type';
    const data = publicStixRelationshipsDistribution.map((n) => {
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
      return {
        x: finalField.endsWith('_id')
          ? defaultValue(n?.entity)
          : n?.label,
        y: n?.value,
        fillColor: color,
      };
    });
    const chartData = [{
      name: selection.label || t_i18n('Number of relationships'),
      data,
    }];
    const redirectionUtils = finalField.endsWith('_id')
      ? publicStixRelationshipsDistribution.flatMap((n) => {
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

const PublicStixRelationshipsHorizontalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsHorizontalBarsQuery>(
    publicStixRelationshipsHorizontalBarsQuery,
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
          <PublicStixRelationshipsHorizontalBarsComponent
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

export default PublicStixRelationshipsHorizontalBars;
