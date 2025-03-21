import { graphql, useFragment } from 'react-relay';
import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { stixDomainObjectMutationFieldPatch } from '@components/common/stix_domain_objects/StixDomainObjectEditionOverview';
import { StixDomainObjectEditionOverviewFieldPatchMutation } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectEditionOverviewFieldPatchMutation.graphql';
import Alert from '@mui/material/Alert';
import { GraphProvider } from '../../../../components/graph/GraphContext';
import { getObjectsToParse } from '../../../../components/graph/utils/graphUtils';
import { StixCoreObjectOrStixCoreRelationshipContainersGraph_fragment$key } from './__generated__/StixCoreObjectOrStixCoreRelationshipContainersGraph_fragment.graphql';
import { OctiGraphPositions } from '../../../../components/graph/graph.types';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../components/graph/Graph';
import GraphToolbar from '../../../../components/graph/GraphToolbar';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { serializeObjectB64 } from '../../../../utils/object';
import { useFormatter } from '../../../../components/i18n';

export const containersObjectsQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipContainersGraphQuery(
    $id: String!
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    ...StixCoreObjectOrStixCoreRelationshipContainersGraph_fragment
  }
`;

const containersObjectsFragment = graphql`
  fragment StixCoreObjectOrStixCoreRelationshipContainersGraph_fragment on Query {
    containersObjectsOfObject(
      id: $id
      types: $types
      filters: $filters
      search: $search
    ) {
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
      edges {
        node {
          ... on BasicObject {
            id
            standard_id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            created_at
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
          ... on StixDomainObject {
            created
          }
          ... on AttackPattern {
            name
            x_mitre_id
          }
          ... on Campaign {
            name
            first_seen
            last_seen
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
            name
            created
          }
          ... on CourseOfAction {
            name
          }
          ... on Individual {
            name
          }
          ... on Organization {
            name
          }
          ... on Sector {
            name
          }
          ... on System {
            name
          }
          ... on Indicator {
            name
            valid_from
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
            first_seen
            last_seen
          }
          ... on Position {
            name
          }
          ... on City {
            name
          }
          ... on AdministrativeArea {
            name
          }
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
            first_seen
            last_seen
          }
          ... on ThreatActor {
            name
            first_seen
            last_seen
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
            first_seen
            last_seen
          }
          ... on Event {
            name
            start_time
            stop_time
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
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
          ... on StixFile {
            observableName: name
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixRelationship {
            from {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
              }
              ... on StixCoreRelationship {
                relationship_type
              }
            }
            to {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
              }
              ... on StixCoreRelationship {
                relationship_type
              }
            }
          }
          ... on StixRefRelationship {
            created_at
          }
          ... on StixCoreRelationship {
            relationship_type
            start_time
            stop_time
            confidence
            created
            created_at
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
  }
`;

interface StixCoreObjectOrStixCoreRelationshipContainersGraphComponentProps {
  id: string
}

const StixCoreObjectOrStixCoreRelationshipContainersGraphComponent = ({
  id,
}: StixCoreObjectOrStixCoreRelationshipContainersGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();

  const [commitEditPositions] = useApiMutation<StixDomainObjectEditionOverviewFieldPatchMutation>(
    stixDomainObjectMutationFieldPatch,
  );

  const savePositions = (positions: OctiGraphPositions) => {
    commitEditPositions({
      variables: {
        id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [serializeObjectB64(positions)],
        }],
      },
    });
  };

  const headerHeight = 64;
  const paddingHeight = 25;
  const breadcrumbHeight = 38;
  const titleHeight = 44;
  const tabsHeight = 72;
  const filtersHeight = 48;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + titleHeight + tabsHeight + breadcrumbHeight + filtersHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `-${theme.spacing(3)}`,
    marginTop: 0,
    height: `calc(100vh - ${totalHeight}px)`,
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <Graph parentRef={ref} onPositionsChanged={savePositions}>
        <GraphToolbar />
      </Graph>
    </div>
  );
};

interface StixCoreObjectOrStixCoreRelationshipContainersGraphProps {
  id: string
  positions: OctiGraphPositions
  data: StixCoreObjectOrStixCoreRelationshipContainersGraph_fragment$key
}

const StixCoreObjectOrStixCoreRelationshipContainersGraph = ({
  id,
  data,
  positions,
}: StixCoreObjectOrStixCoreRelationshipContainersGraphProps) => {
  const { t_i18n } = useFormatter();
  const localStorageKey = `analyses-graph-${id}`;

  const { containersObjectsOfObject } = useFragment(containersObjectsFragment, data);
  const objects = useMemo(() => {
    return containersObjectsOfObject
      ? getObjectsToParse({ objects: containersObjectsOfObject })
      : [];
  }, [containersObjectsOfObject]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
      context='analyses'
    >
      <Alert
        sx={{
          position: 'absolute',
          bottom: 4,
          zIndex: 99,
          right: 4,
        }}
        severity="warning"
      >
        {`${t_i18n('Limitations applied, number of fully loaded containers: ')} ${containersObjectsOfObject?.pageInfo.globalCount}. ${t_i18n('Open this entity in an investigation to be able to see all objects.')}`}
      </Alert>
      <StixCoreObjectOrStixCoreRelationshipContainersGraphComponent
        id={id}
      />
    </GraphProvider>
  );
};

export default StixCoreObjectOrStixCoreRelationshipContainersGraph;
