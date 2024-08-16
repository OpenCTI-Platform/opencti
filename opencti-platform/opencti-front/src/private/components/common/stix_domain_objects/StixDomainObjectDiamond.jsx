import React, { useCallback } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import ReactFlow, { addEdge, MarkerType, ReactFlowProvider, useEdgesState, useNodesState } from 'reactflow';
import nodeTypes from './diamond/types/nodes';
import edgeTypes from './diamond/types/edges';
import { ErrorBoundary } from '../../Error';
import { stixDomainObjectThreatDiamondQuery } from './StixDomainObjectThreatDiamondQuery';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    overflow: 'hidden',
  },
}));

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = { padding: 0.1 };
const defaultEdgeOptions = {
  type: 'straight',
  markerEnd: { type: MarkerType.Arrow },
  style: { strokeWidth: 2, strokeDasharray: '3 3' },
};

const StixDomainObjectDiamondComponent = ({ entityLink, data }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { stixDomainObject } = data;
  const initialNodes = [
    {
      id: 'diamond',
      type: 'diamond',
      data: {
        key: 'diamond',
        name: stixDomainObject.name,
      },
      position: { x: 100, y: 100 },
    },
    {
      id: 'infrastructure',
      type: 'infrastructure',
      data: {
        key: 'infrastructure',
        stixDomainObject,
        entityLink,
      },
      position: { x: 490, y: 60 },
    },
    {
      id: 'adversary',
      type: 'adversary',
      data: {
        key: 'adversary',
        stixDomainObject,
        entityLink,
      },
      position: { x: 10, y: -240 },
    },
    {
      id: 'victimology',
      type: 'victimology',
      data: {
        key: 'victimology',
        stixDomainObject,
        entityLink,
      },
      position: { x: 10, y: 450 },
    },
    {
      id: 'capabilities',
      type: 'capabilities',
      data: {
        key: 'capabilities',
        stixDomainObject,
        entityLink,
      },
      position: { x: -470, y: 60 },
    },
  ];
  const initialEdges = [
    {
      id: 'adversary',
      type: 'card',
      source: 'diamond',
      sourceHandle: 'adversary',
      target: 'adversary',
      data: {
        label: t_i18n('Adversary'),
      },
    },
    {
      id: 'infrastructure',
      type: 'card',
      source: 'diamond',
      sourceHandle: 'infrastructure',
      target: 'infrastructure',
      data: {
        label: t_i18n('Infrastructure'),
      },
    },
    {
      id: 'victimology',
      type: 'card',
      source: 'diamond',
      sourceHandle: 'victimology',
      target: 'victimology',
      data: {
        label: t_i18n('Victimology'),
      },
    },
    {
      id: 'capabilities',
      type: 'card',
      source: 'diamond',
      sourceHandle: 'capabilities',
      target: 'capabilities',
      data: {
        label: t_i18n('Capabilities'),
      },
    },
  ];
  const Flow = () => {
    const [nodes, , onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
    const onConnect = useCallback(
      (params) => setEdges((eds) => addEdge(params, eds)),
      [setEdges],
    );
    return (
      <>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          defaultViewport={defaultViewport}
          defaultEdgeOptions={defaultEdgeOptions}
          minZoom={0.2}
          fitView={true}
          fitViewOptions={fitViewOptions}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          nodesDraggable={false}
          nodesConnectable={false}
          zoomOnDoubleClick={false}
          proOptions={proOptions}
          zoomOnScroll={false}
          preventScrolling={false}
        />
      </>
    );
  };
  return (
    <>
      <ErrorBoundary>
        <div id="container">
          <div className={classes.container} style={{ width: '100%', height: 1000 }}>
            <ReactFlowProvider>
              <Flow />
            </ReactFlowProvider>
          </div>
        </div>
      </ErrorBoundary>
    </>
  );
};

const StixDomainObjectDiamond = createRefetchContainer(
  StixDomainObjectDiamondComponent,
  {
    data: graphql`
      fragment StixDomainObjectDiamond_data on Query {
        stixDomainObject(id: $id) {
          id
          entity_type
          parent_types
          ... on Incident {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            attributedTo: stixCoreRelationships(
              relationship_type: "attributed-to"
              toTypes: ["Campaign", "Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on Campaign {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            attributedTo: stixCoreRelationships(
              relationship_type: "attributed-to"
              toTypes: ["Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on IntrusionSet {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            attributedTo: stixCoreRelationships(
              relationship_type: "attributed-to"
              toTypes: ["Threat-Actor-Group", "Threat-Actor-Individual"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on ThreatActor {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on ThreatActor {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on Malware {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            usedBy: stixCoreRelationships(
              relationship_type: "uses"
              fromTypes: ["Threat-Actor-Group", "Threat-Actor-Individual", "Intrusion-Set", "Campaign"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on Tool {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            usedBy: stixCoreRelationships(
              relationship_type: "uses"
              fromTypes: ["Threat-Actor-Group", "Threat-Actor-Individual", "Intrusion-Set", "Campaign"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
          ... on Channel {
            name
            aliases
            targetedCountries: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Country"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Country {
                      name
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Sector"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Sector {
                      name
                    }
                  }
                }
              }
            }
            targetedOrganizations: stixCoreRelationships(
              relationship_type: "targets"
              toTypes: ["Organization"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Organization {
                      name
                    }
                  }
                }
              }
            }
            usedBy: stixCoreRelationships(
              relationship_type: "uses"
              fromTypes: ["Threat-Actor-Group", "Threat-Actor-Individual", "Intrusion-Set", "Campaign"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ... on ThreatActor {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                  }
                }
              }
            }
            attackPatternsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Attack-Pattern"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on AttackPattern {
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
            malwaresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Malware"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Malware {
                      name
                    }
                  }
                }
              }
            }
            toolsAndChannelsUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Tool", "Channel"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ... on Tool {
                      name
                    }
                    ... on Channel {
                      name
                    }
                  }
                }
              }
            }
            relatedDomains: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["Domain-Name", "Hostname"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            relatedIPs: stixCoreRelationships(
              relationship_type: "related-to"
              fromTypes: ["IPv4-Addr", "IPv6-Addr"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  from {
                    ...on StixCyberObservable {
                      representative {
                        main
                      }
                    }
                  }
                }
              }
            }
            infrastructuresUsed: stixCoreRelationships(
              relationship_type: "uses"
              toTypes: ["Infrastructure"]
              first: 10
              orderBy: created_at
              orderMode: desc
            ) {
              edges {
                node {
                  to {
                    ...on Infrastructure {
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectThreatDiamondQuery,
);

export default StixDomainObjectDiamond;
