import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { useRef } from 'react';
import { getDefaultWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixCoreObjectsListQuery } from './__generated__/PublicStixCoreObjectsListQuery.graphql';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetColumn } from '../../../../utils/widget/widget';

const publicStixCoreObjectsListQuery = graphql`
  query PublicStixCoreObjectsListQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjects(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          ... on StixDomainObject {
            created
            modified
          }
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
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
          ... on Task {
            name
            description
          }
          ... on StixCyberObservable {
            observable_value
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectLabel {
            id
            value
            color
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on StixDomainObject {
            status {
              id
              order
              template {
                name
                color
              }
            }
            workflowEnabled
          }
        }
      }
    }
  }
`;

interface PublicStixCoreObjectsListComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsListQuery>
  rootRef: DataTableProps['rootRef']
  widgetId: string
  columns: WidgetColumn[]
}

const PublicStixCoreObjectsListComponent = ({
  queryRef,
  rootRef,
  widgetId,
  columns,
}: PublicStixCoreObjectsListComponentProps) => {
  const { publicStixCoreObjects } = usePreloadedQuery(
    publicStixCoreObjectsListQuery,
    queryRef,
  );

  if (publicStixCoreObjects?.edges && publicStixCoreObjects.edges.length > 0) {
    return (
      <WidgetListCoreObjects
        data={[...publicStixCoreObjects.edges]}
        publicWidget
        rootRef={rootRef}
        widgetId={widgetId}
        pageSize={100}
        columns={columns}
      />
    );
  }
  return <WidgetNoData />;
};

PublicStixCoreObjectsListComponent.displayName = 'PublicStixCoreObjectsListComponent';

const PublicStixCoreObjectsList = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsListQuery>(
    publicStixCoreObjectsListQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  const selection = dataSelection[0];
  const columns = selection.columns ?? getDefaultWidgetColumns('entities');

  const rootRef = useRef<HTMLDivElement>(null);

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <PublicStixCoreObjectsListComponent
              queryRef={queryRef}
              columns={[...columns]}
              rootRef={rootRef.current ?? undefined}
              widgetId={id}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inElement} />
        )}
      </div>
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsList;
