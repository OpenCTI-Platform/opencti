import { graphql, useFragment } from 'react-relay';
import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { knowledgeCorrelationStixCoreObjectQuery, knowledgeCorrelationStixCoreRelationshipQuery } from '@components/common/containers/KnowledgeCorrelationQuery';
import useIncidentKnowledgeCorrelationEdit from './useIncidentKnowledgeCorrelationEdit';
import type { Theme } from '../../../../components/Theme';
import { IncidentKnowledgeCorrelation_fragment$data, IncidentKnowledgeCorrelation_fragment$key } from './__generated__/IncidentKnowledgeCorrelation_fragment.graphql';
import Graph from '../../../../utils/graph/Graph';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { encodeGraphData } from '../../../../utils/Graph';
import { getObjectsToParse } from '../../../../utils/graph/utils/graphUtils';
import { GraphProvider } from '../../../../utils/graph/GraphContext';

const incidentCorrelationFragment = graphql`
  fragment IncidentKnowledgeCorrelation_fragment on CaseIncident {
    id
    name
    x_opencti_graph_data
    confidence
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
    objects {
      edges {
        node {
          ... on BasicObject {
            id
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
            reports(first: 20) {
              edges {
                node {
                  id
                  name
                  published
                  confidence
                  entity_type
                  parent_types
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
            groupings(first: 20) {
              edges {
                node {
                  id
                  name
                  context
                  confidence
                  entity_type
                  parent_types
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
            cases(first: 20) {
              edges {
                node {
                  id
                  name
                  confidence
                  entity_type
                  parent_types
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
          ... on StixCyberObservable {
            observable_value
            reports(first: 20) {
              edges {
                node {
                  id
                  name
                  published
                  confidence
                  entity_type
                  parent_types
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
            groupings(first: 20) {
              edges {
                node {
                  id
                  name
                  context
                  confidence
                  entity_type
                  parent_types
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
            cases(first: 20) {
              edges {
                node {
                  id
                  name
                  confidence
                  entity_type
                  parent_types
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
          ... on StixFile {
            observableName: name
          }
        }
      }
    }
  }
`;

export const incidentKnowledgeCorrelationQuery = graphql`
  query IncidentKnowledgeCorrelationQuery($id: String!) {
    caseIncident(id: $id) {
      ...IncidentKnowledgeCorrelation_fragment
    }
  }
`;

interface IncidentKnowledgeCorrelationComponentProps {
  incident: IncidentKnowledgeCorrelation_fragment$data
}

const IncidentKnowledgeCorrelationComponent = ({
  incident,
}: IncidentKnowledgeCorrelationComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();

  const [commitEditPositions] = useIncidentKnowledgeCorrelationEdit();

  const headerHeight = 64;
  const paddingHeight = 25;
  const breadcrumbHeight = 38;
  const titleHeight = 44;
  const tabsHeight = 72;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + breadcrumbHeight + titleHeight + tabsHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `-${theme.spacing(3)}`,
    height: `calc(100vh - ${totalHeight}px)`,
  };

  const savePositions = (positions: OctiGraphPositions) => {
    commitEditPositions({
      variables: {
        id: incident.id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [encodeGraphData(positions)],
        }],
      },
    });
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <Graph
        parentRef={ref}
        onPositionsChanged={savePositions}
        stixCoreObjectRefetchQuery={knowledgeCorrelationStixCoreObjectQuery}
        relationshipRefetchQuery={knowledgeCorrelationStixCoreRelationshipQuery}
      />
    </div>
  );
};

interface IncidentKnowledgeCorrelationProps {
  data: IncidentKnowledgeCorrelation_fragment$key
}

const IncidentKnowledgeCorrelation = ({
  data,
}: IncidentKnowledgeCorrelationProps) => {
  const incident = useFragment(incidentCorrelationFragment, data);
  const incidentData = useMemo(() => getObjectsToParse(incident), [incident]);
  const localStorageKey = `incident-knowledge-correlation-${incident.id}`;

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      data={incidentData}
      context='correlation'
    >
      <IncidentKnowledgeCorrelationComponent incident={incident} />
    </GraphProvider>
  );
};

export default IncidentKnowledgeCorrelation;
