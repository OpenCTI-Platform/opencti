import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ForceGraph3D from 'react-force-graph-3d';
import SpriteText from 'three-spritetext';
import ForceGraph2D from 'react-force-graph-2d';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import { withRouter } from 'react-router-dom';
import inject18n from '../../../../components/i18n';
import InvestigationGraphBar from './InvestigationGraphBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import {
  applyFilters,
  buildGraphData,
  decodeGraphData,
  encodeGraphData,
  linkPaint,
  nodeAreaPaint,
  nodePaint,
  nodeThreePaint,
} from '../../../../utils/Graph';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import Theme from '../../../../components/ThemeDark';
import { investigationAddStixCoreObjectsLinesRelationDeleteMutation } from './InvestigationAddStixCoreObjectsLines';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';

const PARAMETERS$ = new Subject().pipe(debounce(() => timer(2000)));
const POSITIONS$ = new Subject().pipe(debounce(() => timer(2000)));

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '7px 274px 0 215px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 64,
  },
});

export const investigationGraphQuery = graphql`
  query InvestigationGraphQuery($id: String) {
    workspace(id: $id) {
      ...InvestigationGraph_workspace
    }
  }
`;

const investigationGraphStixCoreObjectQuery = graphql`
  query InvestigationGraphStixCoreObjectQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      parent_types
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition
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
      ... on XOpenCTIIncident {
        name
        description
      }
      ... on StixCyberObservable {
        observable_value
      }
    }
  }
`;

const investigationGraphStixCoreRelationshipQuery = graphql`
  query InvestigationGraphStixCoreRelationshipQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      entity_type
      parent_types
      start_time
      stop_time
      confidence
      relationship_type
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
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition
          }
        }
      }
    }
  }
`;

const investigationGraphStixRelationshipsQuery = graphql`
  query InvestigationGraphStixRelationshipsQuery(
    $elementId: String!
    $relationship_type: String
    $elementWithTargetTypes: [String]
    $count: Int
  ) {
    stixRelationships(
      elementId: $elementId
      relationship_type: $relationship_type
      elementWithTargetTypes: $elementWithTargetTypes
      first: $count
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          ... on StixCoreRelationship {
            start_time
            stop_time
            confidence
            relationship_type
            created_at
            updated_at
            createdBy {
              ... on Identity {
                id
                name
                entity_type
              }
            }
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
            }
          }
          ... on StixSightingRelationship {
            first_seen
            last_seen
            created_at
            updated_at
            createdBy {
              ... on Identity {
                id
                name
                entity_type
              }
            }
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
            }
          }
          ... on StixCyberObservableRelationship {
            start_time
            stop_time
            relationship_type
            created_at
            updated_at
          }
          from {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            ... on XOpenCTIIncident {
              name
              description
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
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
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
            }
          }
          to {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            ... on XOpenCTIIncident {
              name
              description
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
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
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

const investigationGraphRelationsAddMutation = graphql`
  mutation InvestigationGraphRelationsAddMutation(
    $id: ID!
    $input: StixMetaRelationshipsAddInput
  ) {
    workspaceEdit(id: $id) {
      relationsAdd(input: $input) {
        id
      }
    }
  }
`;

class InvestigationGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.initialized = false;
    this.graph = React.createRef();
    this.selectedNodes = new Set();
    this.selectedLinks = new Set();
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-workspace-${this.props.workspace.id}-investigation`,
    );
    this.zoom = R.propOr(null, 'zoom', params);
    this.graphObjects = R.map((n) => n.node, props.workspace.objects.edges);
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(props.workspace.graph_data),
      props.t,
    );
    const stixCoreObjectsTypes = R.propOr([], 'stixCoreObjectsTypes', params);
    const markedBy = R.propOr([], 'markedBy', params);
    const createdBy = R.propOr([], 'createdBy', params);
    this.state = {
      mode3D: R.propOr(false, 'mode3D', params),
      modeTree: false,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData: applyFilters(
        this.graphData,
        stixCoreObjectsTypes,
        markedBy,
        createdBy,
      ),
      numberOfSelectedNodes: 0,
      numberOfSelectedLinks: 0,
    };
  }

  initialize() {
    if (this.initialized) return;
    if (this.graph && this.graph.current) {
      this.graph.current.zoomToFit(0, 150);
      if (this.zoom && this.zoom.k && !this.state.mode3D) {
        this.graph.current.zoom(this.zoom.k, 400);
      }
      this.graph.current.d3Force('link').distance(50);
    }
    this.initialized = true;
  }

  componentDidMount() {
    this.subscription = PARAMETERS$.subscribe({
      next: () => this.saveParameters(),
    });
    this.subscription = POSITIONS$.subscribe({
      next: () => this.savePositions(),
    });
    setTimeout(() => this.initialize(), 1500);
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  saveParameters(refreshGraphData = false) {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-workspace-${this.props.workspace.id}-investigation`,
      { zoom: this.zoom, ...this.state },
    );
    if (refreshGraphData) {
      this.setState({
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
        ),
      });
    }
  }

  savePositions() {
    const initialPositions = R.indexBy(
      R.prop('id'),
      R.map((n) => ({ id: n.id, x: n.fx, y: n.fy }), this.graphData.nodes),
    );
    const newPositions = R.indexBy(
      R.prop('id'),
      R.map((n) => ({ id: n.id, x: n.fx, y: n.fy }), this.state.graphData.nodes),
    );
    const positions = R.mergeLeft(newPositions, initialPositions);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'graph_data',
          value: encodeGraphData(positions),
        },
      },
    });
  }

  handleToggle3DMode() {
    this.setState({ mode3D: !this.state.mode3D }, () => this.saveParameters());
  }

  handleToggleTreeMode() {
    this.setState({ modeTree: !this.state.modeTree }, () => this.saveParameters());
  }

  handleToggleStixCoreObjectType(type) {
    const { stixCoreObjectsTypes } = this.state;
    if (stixCoreObjectsTypes.includes(type)) {
      this.setState(
        {
          stixCoreObjectsTypes: R.filter(
            (t) => t !== type,
            stixCoreObjectsTypes,
          ),
        },
        () => this.saveParameters(true),
      );
    } else {
      this.setState(
        { stixCoreObjectsTypes: R.append(type, stixCoreObjectsTypes) },
        () => this.saveParameters(true),
      );
    }
  }

  handleToggleMarkedBy(markingDefinition) {
    const { markedBy } = this.state;
    if (markedBy.includes(markingDefinition)) {
      this.setState(
        {
          markedBy: R.filter((t) => t !== markingDefinition, markedBy),
        },
        () => this.saveParameters(true),
      );
    } else {
      // eslint-disable-next-line max-len
      this.setState({ markedBy: R.append(markingDefinition, markedBy) }, () => this.saveParameters(true));
    }
  }

  handleToggleCreateBy(createdByRef) {
    const { createdBy } = this.state;
    if (createdBy.includes(createdByRef)) {
      this.setState(
        {
          createdBy: R.filter((t) => t !== createdByRef, createdBy),
        },
        () => this.saveParameters(true),
      );
    } else {
      this.setState(
        { createdBy: R.append(createdByRef, createdBy) }, () => this.saveParameters(true),
      );
    }
  }

  handleZoomToFit() {
    this.graph.current.zoomToFit(400, 150);
  }

  handleZoomEnd(zoom) {
    if (
      this.initialized
      && (zoom.k !== this.zoom?.k
        || zoom.x !== this.zoom?.x
        || zoom.y !== this.zoom?.y)
    ) {
      this.zoom = zoom;
      PARAMETERS$.next({ action: 'SaveParameters' });
    }
  }

  // eslint-disable-next-line class-methods-use-this
  handleDragEnd() {
    POSITIONS$.next({ action: 'SavePositions' });
  }

  handleNodeClick(node, event) {
    if (event.ctrlKey || event.shiftKey || event.altKey) {
      if (this.selectedNodes.has(node)) {
        this.selectedNodes.delete(node);
      } else {
        this.selectedNodes.add(node);
      }
    } else {
      const untoggle = this.selectedNodes.has(node) && this.selectedNodes.size === 1;
      this.selectedNodes.clear();
      this.selectedLinks.clear();
      if (!untoggle) this.selectedNodes.add(node);
    }
    this.setState({
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleLinkClick(link, event) {
    if (event.ctrlKey || event.shiftKey || event.altKey) {
      if (this.selectedLinks.has(link)) {
        this.selectedLinks.delete(link);
      } else {
        this.selectedLinks.add(link);
      }
    } else {
      const untoggle = this.selectedLinks.has(link) && this.selectedLinks.size === 1;
      this.selectedNodes.clear();
      this.selectedLinks.clear();
      if (!untoggle) {
        this.selectedLinks.add(link);
      }
    }
    this.setState({
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleBackgroundClick() {
    this.selectedNodes.clear();
    this.selectedLinks.clear();
    this.setState({
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleAddEntity(stixCoreObject) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreObject.id)) return;
    this.graphObjects = [stixCoreObject, ...this.graphObjects];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    this.setState(
      {
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
        ),
      },
      () => {
        setTimeout(() => this.handleZoomToFit(), 1000);
      },
    );
  }

  handleDelete(stixCoreObject) {
    const relationshipsToRemove = R.filter(
      (n) => n.from?.id === stixCoreObject.id || n.to?.id === stixCoreObject.id,
      this.graphObjects,
    );
    this.graphObjects = R.filter(
      (n) => n.id !== stixCoreObject.id
        && n.from?.id !== stixCoreObject.id
        && n.to?.id !== stixCoreObject.id,
      this.graphObjects,
    );
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    R.forEach((n) => {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: this.props.workspace.id,
          toId: n.id,
          relationship_type: 'object',
        },
      });
    }, relationshipsToRemove);
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
      ),
    });
  }

  handleDeleteSelected() {
    // Remove selected links
    const selectedLinks = Array.from(this.selectedLinks);
    const selectedLinksIds = R.map((n) => n.id, selectedLinks);
    R.forEach(
      (n) => commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: this.props.workspace.id,
          toId: n.id,
          relationship_type: 'object',
        },
      }),
      this.selectedLinks,
    );
    this.graphObjects = R.filter(
      (n) => !R.includes(n.id, selectedLinksIds),
      this.graphObjects,
    );
    this.selectedLinks.clear();

    // Remove selected nodes
    const selectedNodes = Array.from(this.selectedNodes);
    const selectedNodesIds = R.map((n) => n.id, selectedNodes);
    const relationshipsToRemove = R.filter(
      (n) => R.includes(n.from?.id, selectedNodesIds)
        || R.includes(n.to?.id, selectedNodesIds),
      this.graphObjects,
    );
    this.graphObjects = R.filter(
      (n) => !R.includes(n.id, selectedNodesIds)
        && !R.includes(n.from?.id, selectedNodesIds)
        && !R.includes(n.to?.id, selectedNodesIds),
      this.graphObjects,
    );
    R.forEach((n) => {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: this.props.workspace.id,
          toId: n.id,
          relationship_type: 'object',
        },
      });
    }, relationshipsToRemove);
    R.forEach((n) => {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: this.props.workspace.id,
          toId: n.id,
          relationship_type: 'object',
        },
      });
    }, selectedNodes);
    this.selectedNodes.clear();
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
      ),
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleCloseEntityEdition(entityId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreObjectQuery, {
        id: entityId,
      }).then((data) => {
        const { stixCoreObject } = data;
        this.graphObjects = R.map(
          (n) => (n.id === stixCoreObject.id ? stixCoreObject : n),
          this.graphObjects,
        );
        this.graphData = buildGraphData(
          this.graphObjects,
          decodeGraphData(this.props.workspace.graph_data),
          this.props.t,
        );
        this.setState({
          graphData: applyFilters(
            this.graphData,
            this.state.stixCoreObjectsTypes,
            this.state.markedBy,
            this.state.createdBy,
          ),
        });
      });
    }, 1500);
  }

  handleCloseRelationEdition(relationId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreRelationshipQuery, {
        id: relationId,
      }).then((data) => {
        const { stixCoreRelationship } = data;
        this.graphObjects = R.map(
          (n) => (n.id === stixCoreRelationship.id ? stixCoreRelationship : n),
          this.graphObjects,
        );
        this.graphData = buildGraphData(
          this.graphObjects,
          decodeGraphData(this.props.workspace.graph_data),
          this.props.t,
        );
        this.setState({
          graphData: applyFilters(
            this.graphData,
            this.state.stixCoreObjectsTypes,
            this.state.markedBy,
            this.state.createdBy,
          ),
        });
      });
    }, 1500);
  }

  handleSelectAll() {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    R.map((n) => this.selectedNodes.add(n), this.state.graphData.nodes);
    this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
  }

  handleSelectByType(type) {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    R.map(
      (n) => n.entity_type === type && this.selectedNodes.add(n),
      this.state.graphData.nodes,
    );
    this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
  }

  // eslint-disable-next-line class-methods-use-this
  async handleExpandElements(filters) {
    const selectedNodes = Array.from(this.selectedNodes);
    const selectedNodesIds = R.map((n) => n.id, selectedNodes);
    let newElementsIds = [];
    for (const n of selectedNodesIds) {
      // eslint-disable-next-line no-await-in-loop
      const newElements = await fetchQuery(
        investigationGraphStixRelationshipsQuery,
        {
          elementId: n,
          relationship_type:
            filters.relationship_type === 'All'
              ? null
              : filters.relationship_type,
          elementWithTargetTypes: [
            filters.entity_type === 'All' ? null : filters.entity_type,
          ],
          count: filters.limit,
        },
      ).then((data) => {
        const currentElementsIds = R.map((k) => k.id, this.graphObjects);
        const newNodes = R.pipe(
          R.map((k) => (k.node.from.id === n ? k.node.to : k.node.from)),
          R.filter((k) => !currentElementsIds.includes(k.id)),
        )(data.stixRelationships.edges);
        const newRelationships = R.pipe(
          R.map((k) => k.node),
          R.filter((k) => !currentElementsIds.includes(k.id)),
        )(data.stixRelationships.edges);
        return [...newNodes, ...newRelationships];
      });
      newElementsIds = [...R.map((k) => k.id, newElements), ...newElementsIds];
      this.graphObjects = [...newElements, ...this.graphObjects];
    }
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    this.setState(
      {
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
        ),
      },
      () => {
        commitMutation({
          mutation: investigationGraphRelationsAddMutation,
          variables: {
            id: this.props.workspace.id,
            input: {
              toIds: newElementsIds,
              relationship_type: 'object',
            },
          },
        });
        setTimeout(() => this.handleZoomToFit(), 1000);
      },
    );
  }

  render() {
    const { workspace } = this.props;
    const {
      mode3D,
      modeTree,
      stixCoreObjectsTypes: currentStixCoreObjectsTypes,
      markedBy: currentMarkedBy,
      createdBy: currentCreatedBy,
      graphData,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
    } = this.state;
    const width = window.innerWidth - 210;
    const height = window.innerHeight - 180;
    const stixCoreObjectsTypes = R.uniq(
      R.map((n) => n.entity_type, this.graphData.nodes),
    );
    const markedBy = R.uniqBy(
      R.prop('id'),
      R.flatten(R.map((n) => n.markedBy, this.graphData.nodes)),
    );
    const createdBy = R.uniqBy(
      R.prop('id'),
      R.map((n) => n.createdBy, this.graphData.nodes),
    );
    return (
      <div>
        <InvestigationGraphBar
          handleToggle3DMode={this.handleToggle3DMode.bind(this)}
          currentMode3D={mode3D}
          handleToggleTreeMode={this.handleToggleTreeMode.bind(this)}
          currentModeTree={modeTree}
          handleZoomToFit={this.handleZoomToFit.bind(this)}
          handleToggleCreatedBy={this.handleToggleCreateBy.bind(this)}
          handleToggleStixCoreObjectType={this.handleToggleStixCoreObjectType.bind(
            this,
          )}
          handleToggleMarkedBy={this.handleToggleMarkedBy.bind(this)}
          stixCoreObjectsTypes={stixCoreObjectsTypes}
          currentStixCoreObjectsTypes={currentStixCoreObjectsTypes}
          markedBy={markedBy}
          currentMarkedBy={currentMarkedBy}
          createdBy={createdBy}
          currentCreatedBy={currentCreatedBy}
          handleSelectAll={this.handleSelectAll.bind(this)}
          handleSelectByType={this.handleSelectByType.bind(this)}
          workspace={workspace}
          onAdd={this.handleAddEntity.bind(this)}
          onDelete={this.handleDelete.bind(this)}
          handleExpandElements={this.handleExpandElements.bind(this)}
          handleDeleteSelected={this.handleDeleteSelected.bind(this)}
          selectedNodes={Array.from(this.selectedNodes)}
          selectedLinks={Array.from(this.selectedLinks)}
          numberOfSelectedNodes={numberOfSelectedNodes}
          numberOfSelectedLinks={numberOfSelectedLinks}
          handleCloseEntityEdition={this.handleCloseEntityEdition.bind(this)}
          handleCloseRelationEdition={this.handleCloseRelationEdition.bind(
            this,
          )}
        />
        {mode3D ? (
          <ForceGraph3D
            ref={this.graph}
            width={width}
            height={height}
            backgroundColor={Theme.palette.background.default}
            graphData={graphData}
            nodeThreeObjectExtend={true}
            nodeThreeObject={nodeThreePaint}
            linkColor={(link) => (this.selectedLinks.has(link)
              ? Theme.palette.secondary.main
              : Theme.palette.primary.main)
            }
            linkWidth={0.2}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={0.99}
            linkThreeObjectExtend={true}
            linkThreeObject={(link) => {
              const sprite = new SpriteText(link.label);
              sprite.color = 'lightgrey';
              sprite.textHeight = 1.5;
              return sprite;
            }}
            linkPositionUpdate={(sprite, { start, end }) => {
              const middlePos = Object.assign(
                ...['x', 'y', 'z'].map((c) => ({
                  [c]: start[c] + (end[c] - start[c]) / 2,
                })),
              );
              Object.assign(sprite.position, middlePos);
            }}
            onNodeClick={this.handleNodeClick.bind(this)}
            onNodeRightClick={(node) => {
              // eslint-disable-next-line no-param-reassign
              node.fx = undefined;
              // eslint-disable-next-line no-param-reassign
              node.fy = undefined;
              // eslint-disable-next-line no-param-reassign
              node.fz = undefined;
              this.handleDragEnd();
              this.forceUpdate();
            }}
            onNodeDrag={(node, translate) => {
              if (this.selectedNodes.has(node)) {
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node)
                  // eslint-disable-next-line no-shadow
                  .forEach((node) => ['x', 'y', 'z'].forEach(
                    // eslint-disable-next-line no-param-reassign,no-return-assign
                    (coord) => (node[`f${coord}`] = node[coord] + translate[coord]),
                  ));
              }
            }}
            onNodeDragEnd={(node) => {
              if (this.selectedNodes.has(node)) {
                // finished moving a selected node
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node) // don't touch node being dragged
                  // eslint-disable-next-line no-shadow
                  .forEach((node) => {
                    ['x', 'y'].forEach(
                      // eslint-disable-next-line no-param-reassign,no-return-assign
                      (coord) => (node[`f${coord}`] = undefined),
                    );
                    // eslint-disable-next-line no-param-reassign
                    node.fx = node.x;
                    // eslint-disable-next-line no-param-reassign
                    node.fy = node.y;
                    // eslint-disable-next-line no-param-reassign
                    node.fz = node.z;
                  });
              }
              // eslint-disable-next-line no-param-reassign
              node.fx = node.x;
              // eslint-disable-next-line no-param-reassign
              node.fy = node.y;
              // eslint-disable-next-line no-param-reassign
              node.fz = node.z;
            }}
            onLinkClick={this.handleLinkClick.bind(this)}
            onBackgroundClick={this.handleBackgroundClick.bind(this)}
          />
        ) : (
          <ForceGraph2D
            ref={this.graph}
            width={width}
            height={height}
            graphData={graphData}
            onZoomEnd={this.handleZoomEnd.bind(this)}
            nodeRelSize={4}
            nodeCanvasObject={
              (node, ctx) => nodePaint(node, node.color, ctx, this.selectedNodes.has(node))
            }
            nodePointerAreaPaint={nodeAreaPaint}
            // linkDirectionalParticles={(link) => (this.selectedLinks.has(link) ? 20 : 0)}
            // linkDirectionalParticleWidth={1}
            // linkDirectionalParticleSpeed={() => 0.004}
            linkCanvasObjectMode={() => 'after'}
            linkCanvasObject={linkPaint}
            linkColor={(link) => (this.selectedLinks.has(link)
              ? Theme.palette.secondary.main
              : Theme.palette.primary.main)
            }
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={0.99}
            onNodeClick={this.handleNodeClick.bind(this)}
            onNodeRightClick={(node) => {
              // eslint-disable-next-line no-param-reassign
              node.fx = undefined;
              // eslint-disable-next-line no-param-reassign
              node.fy = undefined;
              this.handleDragEnd();
              this.forceUpdate();
            }}
            onNodeDrag={(node, translate) => {
              if (this.selectedNodes.has(node)) {
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node)
                  // eslint-disable-next-line no-shadow
                  .forEach((node) => ['x', 'y'].forEach(
                    // eslint-disable-next-line no-param-reassign,no-return-assign
                    (coord) => (node[`f${coord}`] = node[coord] + translate[coord]),
                  ));
              }
            }}
            onNodeDragEnd={(node) => {
              if (this.selectedNodes.has(node)) {
                // finished moving a selected node
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node) // don't touch node being dragged
                  // eslint-disable-next-line no-shadow
                  .forEach((node) => {
                    ['x', 'y'].forEach(
                      // eslint-disable-next-line no-param-reassign,no-return-assign
                      (coord) => (node[`f${coord}`] = undefined),
                    );
                    // eslint-disable-next-line no-param-reassign
                    node.fx = node.x;
                    // eslint-disable-next-line no-param-reassign
                    node.fy = node.y;
                  });
              }
              // eslint-disable-next-line no-param-reassign
              node.fx = node.x;
              // eslint-disable-next-line no-param-reassign
              node.fy = node.y;
              this.handleDragEnd();
            }}
            onLinkClick={this.handleLinkClick.bind(this)}
            onBackgroundClick={this.handleBackgroundClick.bind(this)}
          />
        )}
      </div>
    );
  }
}

InvestigationGraphComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const InvestigationGraph = createFragmentContainer(
  InvestigationGraphComponent,
  {
    workspace: graphql`
      fragment InvestigationGraph_workspace on Workspace {
        id
        identifier
        name
        description
        manifest
        tags
        owner {
          id
          name
        }
        objects(all: true) {
          edges {
            node {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on StixCoreObject {
                created_at
                updated_at
                createdBy {
                  ... on Identity {
                    id
                    name
                    entity_type
                  }
                }
                objectMarking {
                  edges {
                    node {
                      id
                      definition
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
              ... on XOpenCTIIncident {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
              }
              ... on StixCoreRelationship {
                relationship_type
                start_time
                stop_time
                confidence
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
                created_at
                updated_at
                createdBy {
                  ... on Identity {
                    id
                    name
                    entity_type
                  }
                }
                objectMarking {
                  edges {
                    node {
                      id
                      definition
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
);

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(InvestigationGraph);
