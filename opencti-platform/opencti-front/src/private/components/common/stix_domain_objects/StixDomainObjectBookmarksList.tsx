import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetBookmarks from '../../../../components/dashboard/WidgetBookmarks';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import { StixDomainObjectBookmarksListQuery, StixDomainObjectsOrdering } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectBookmarksListQuery.graphql';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import React, { Suspense } from 'react';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { OrderingMode } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';

const stixDomainObjectBookmarksListQuery = graphql`
  query StixDomainObjectBookmarksListQuery($types: [String], $first: Int, $filters: FilterGroup, $orderBy: StixDomainObjectsOrdering, $orderMode: OrderingMode) {
    bookmarks(types: $types, first: $first, filters: $filters, orderBy: $orderBy, orderMode: $orderMode) {
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
  return edges.length === 0
    ? <WidgetNoData />
    : <WidgetBookmarks bookmarks={edges} />;
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
  const orderBy = (selection.sort_by && selection.sort_by.length > 0
    ? selection.sort_by
    : 'created_at') as StixDomainObjectsOrdering | null | undefined;
  const orderMode = (selection.sort_mode ?? 'asc') as OrderingMode;
  return {
    first: selection.number ?? 10,
    orderBy,
    orderMode,
    filters: normalizeFilterGroupForBackend(selection.filters),
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
    isMissingSavedFilters,
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

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixDomainObjectBookmarksListComponent
          queryRef={queryRef}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('Bookmarks')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        {renderContent()}
      </div>
    </WidgetContainer>
  );
};

export default StixDomainObjectBookmarksList;
