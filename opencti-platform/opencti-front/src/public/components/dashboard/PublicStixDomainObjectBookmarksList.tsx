import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import WidgetBookmarks from '../../../components/dashboard/WidgetBookmarks';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixDomainObjectBookmarksListQuery } from './__generated__/PublicStixDomainObjectBookmarksListQuery.graphql';

const publicStixDomainObjectBookmarksListQuery = graphql`
  query PublicStixDomainObjectBookmarksListQuery(
    $uriKey: String!
    $widgetId : String!
  ) {
    publicBookmarks(
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          created
          modified
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
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  }
`;

interface PublicStixDomainObjectBookmarksListComponentProps {
  queryRef: PreloadedQuery<PublicStixDomainObjectBookmarksListQuery>
}

const PublicStixDomainObjectBookmarksListComponent = ({
  queryRef,
}: PublicStixDomainObjectBookmarksListComponentProps) => {
  const { publicBookmarks } = usePreloadedQuery(
    publicStixDomainObjectBookmarksListQuery,
    queryRef,
  );

  if (
    publicBookmarks
    && publicBookmarks.edges
    && publicBookmarks.edges.length > 0
  ) {
    return <WidgetBookmarks bookmarks={[...publicBookmarks.edges]} />;
  }
  return <WidgetNoData />;
};

const PublicStixDomainObjectBookmarksList = ({
  uriKey,
  widget,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixDomainObjectBookmarksListQuery>(
    publicStixDomainObjectBookmarksListQuery,
    {
      uriKey,
      widgetId: id,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixDomainObjectBookmarksListComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixDomainObjectBookmarksList;
