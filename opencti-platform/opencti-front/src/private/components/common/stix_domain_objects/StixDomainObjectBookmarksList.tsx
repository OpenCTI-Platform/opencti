import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetBookmarks from '../../../../components/dashboard/WidgetBookmarks';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixDomainObjectBookmarksListQuery } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectBookmarksListQuery.graphql';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import React, { Suspense } from 'react';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

const stixDomainObjectBookmarksListQuery = graphql`
  query StixDomainObjectBookmarksListQuery($types: [String], $first: Int, $filters: FilterGroup) {
    bookmarks(types: $types, first: $first, filters: $filters) {
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

interface StixDomainObjectBookmarksListComponentProps {
  queryRef: PreloadedQuery<StixDomainObjectBookmarksListQuery>;
}

const StixDomainObjectBookmarksListComponent = ({
  queryRef,
}: StixDomainObjectBookmarksListComponentProps) => {
  const data = usePreloadedQuery(stixDomainObjectBookmarksListQuery, queryRef);
  const edges = data?.bookmarks?.edges ?? [];
  return edges.length === 0 ? (
    <WidgetNoData />
  ) : (
    <WidgetBookmarks
      bookmarks={edges}
    />
  );
};

interface StixDomainObjectBookmarksListProps {
  title?: string;
  variant?: string;
  height?: number;
  parameters: { title?: string };
  popover?: React.ReactNode;
  dataSelection: Widget['dataSelection'];
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const buildQueryVariables = (resolvedDataSelection: WidgetDataSelection[]) => {
  const selection = resolvedDataSelection[0];
  return {
    first: 50,
    filters: removeEntityTypeAllFromFilterGroup(selection.filters ?? undefined) as StixDomainObjectBookmarksListQuery['variables']['filters'],
  };
};

const StixDomainObjectBookmarksList = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  title,
  config,
  refreshRate = null,
  host,
}: StixDomainObjectBookmarksListProps) => {
  const { t_i18n } = useFormatter();

  const {
    isMissingHostEntity,
    isPreviewMode,
    queryRef,
  } = useDashboardViz<StixDomainObjectBookmarksListQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixDomainObjectBookmarksListQuery,
    buildQueryVariables,
    config,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('Bookmarks')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        {queryRef && (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <StixDomainObjectBookmarksListComponent
              queryRef={queryRef}
            />
          </Suspense>
        )}
      </div>
    </WidgetContainer>
  );
};

export default StixDomainObjectBookmarksList;
