import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import ForceGraph3D from 'react-force-graph-3d';
import SpriteText from 'three-spritetext';
import ForceGraph2D from 'react-force-graph-2d';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import { withRouter } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import Dialog from '@mui/material/Dialog';
import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import inject18n from '../../../../components/i18n';
import InvestigationGraphBar from './InvestigationGraphBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import {
  applyFilters,
  buildGraphData,
  computeTimeRangeInterval,
  computeTimeRangeValues,
  decodeGraphData,
  encodeGraphData,
  linkPaint,
  nodeAreaPaint,
  nodePaint,
  nodeThreePaint,
} from '../../../../utils/Graph';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import { investigationAddStixCoreObjectsLinesRelationsDeleteMutation } from './InvestigationAddStixCoreObjectsLines';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import WorkspaceHeader from '../WorkspaceHeader';
import SelectField from '../../../../components/SelectField';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';

const PARAMETERS$ = new Subject().pipe(debounce(() => timer(2000)));
const POSITIONS$ = new Subject().pipe(debounce(() => timer(2000)));
const DBL_CLICK_TIMEOUT = 500; // ms

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
      ... on Note {
        attribute_abstract
        content
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
        published
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
      }
      ... on StixFile {
        observableName: name
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
    $relationship_type: [String]
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
          ... on StixMetaRelationship {
            created_at
          }
          ... on StixCoreRelationship {
            start_time
            stop_time
            confidence
            relationship_type
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
            ... on Note {
              attribute_abstract
              content
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
              published
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
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
            }
            ... on StixMetaObject {
              created
            }
            ... on Label {
              value
              color
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on ExternalReference {
              url
              source_name
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
              created
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
              published
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
            }
            ... on StixFile {
              observableName: name
            }
            ... on StixMetaObject {
              created
            }
            ... on Label {
              value
              color
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on ExternalReference {
              url
              source_name
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
              created
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
    this.zoomed = 0;
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
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const sortByDefinition = R.sortBy(
      R.compose(R.toLower, R.prop('definition')),
    );
    const sortByName = R.sortBy(R.compose(R.toLower, R.prop('name')));
    const allStixCoreObjectsTypes = R.pipe(
      R.map((n) => n.entity_type),
      R.uniq,
      R.map((n) => ({
        label: n,
        tlabel: props.t(
          `${n.relationship_type ? 'relationship_' : 'entity_'}${n.entity_type}`,
        ),
      })),
      sortByLabel,
      R.map((n) => n.label),
    )(this.graphData.nodes);
    const allMarkedBy = R.pipe(
      R.map((n) => n.markedBy),
      R.flatten,
      R.uniqBy(R.prop('id')),
      sortByDefinition,
    )(R.union(this.graphData.nodes, this.graphData.links));
    const allCreatedBy = R.pipe(
      R.map((n) => n.createdBy),
      R.uniqBy(R.prop('id')),
      sortByName,
    )(R.union(this.graphData.nodes, this.graphData.links));
    const stixCoreObjectsTypes = R.propOr(
      allStixCoreObjectsTypes,
      'stixCoreObjectsTypes',
      params,
    );
    const markedBy = R.propOr(
      allMarkedBy.map((n) => n.id),
      'markedBy',
      params,
    );
    const createdBy = R.propOr(
      allCreatedBy.map((n) => n.id),
      'createdBy',
      params,
    );
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    this.state = {
      mode3D: R.propOr(false, 'mode3D', params),
      modeFixed: R.propOr(false, 'modeFixed', params),
      modeTree: R.propOr('', 'modeTree', params),
      displayTimeRange: R.propOr(false, 'displayTimeRange', params),
      selectedTimeRangeInterval: timeRangeInterval,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData: applyFilters(
        this.graphData,
        stixCoreObjectsTypes,
        markedBy,
        createdBy,
        [],
        timeRangeInterval,
      ),
      numberOfSelectedNodes: 0,
      numberOfSelectedLinks: 0,
      displayProgress: false,
      width: null,
      height: null,
      zoomed: false,
      keyword: '',
      prevClick: null,
    };
  }

  initialize() {
    if (this.initialized) return;
    if (this.graph && this.graph.current) {
      this.graph.current.d3Force('link').distance(50);
      if (this.state.modeTree !== '') {
        this.graph.current.d3Force('charge').strength(-1000);
      }
      if (this.zoomed < 2) {
        if (this.zoom && this.zoom.k && !this.state.mode3D) {
          this.graph.current.zoom(this.zoom.k, 400);
        } else {
          // eslint-disable-next-line @typescript-eslint/no-this-alias
          const currentContext = this;
          setTimeout(
            () => currentContext.graph
              && currentContext.graph.current
              && currentContext.graph.current.zoomToFit(0, 150),
            1200,
          );
        }
      }
      this.initialized = true;
      this.zoomed += 1;
    }
  }

  componentDidMount() {
    this.subscription = PARAMETERS$.subscribe({
      next: () => this.saveParameters(),
    });
    this.subscription = POSITIONS$.subscribe({
      next: () => this.savePositions(),
    });
    this.initialize();
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
          [],
          this.state.selectedTimeRangeInterval,
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

  handleToggleTreeMode(modeTree) {
    if (modeTree === 'horizontal') {
      this.setState(
        {
          modeTree: this.state.modeTree === 'horizontal' ? '' : 'horizontal',
        },
        () => {
          if (this.state.modeTree === 'horizontal') {
            this.graph.current.d3Force('charge').strength(-1000);
          } else {
            this.graph.current.d3Force('charge').strength(-30);
          }
          this.saveParameters();
        },
      );
    } else if (modeTree === 'vertical') {
      this.setState(
        {
          modeTree: this.state.modeTree === 'vertical' ? '' : 'vertical',
        },
        () => {
          if (this.state.modeTree === 'vertical') {
            this.graph.current.d3Force('charge').strength(-1000);
          } else {
            this.graph.current.d3Force('charge').strength(-30);
          }
          this.saveParameters();
        },
      );
    }
  }

  handleToggleFixedMode() {
    this.setState({ modeFixed: !this.state.modeFixed }, () => {
      this.saveParameters();
      this.handleDragEnd();
      this.forceUpdate();
      this.graph.current.d3ReheatSimulation();
    });
  }

  handleToggleDisplayProgress() {
    this.setState({ displayProgress: !this.state.displayProgress });
  }

  handleToggleDisplayTimeRange() {
    this.setState({ displayTimeRange: !this.state.displayTimeRange }, () => this.saveParameters());
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
      // eslint-disable-next-line max-len
      this.setState({ createdBy: R.append(createdByRef, createdBy) }, () => this.saveParameters(true));
    }
  }

  resetAllFilters(onlyRefresh = false) {
    return new Promise((resolve) => {
      const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
      const sortByDefinition = R.sortBy(
        R.compose(R.toLower, R.prop('definition')),
      );
      const sortByName = R.sortBy(R.compose(R.toLower, R.prop('name')));
      const allStixCoreObjectsTypes = R.pipe(
        R.map((n) => n.entity_type),
        R.uniq,
        R.map((n) => ({
          label: n,
          tlabel: this.props.t(
            `${n.relationship_type ? 'relationship_' : 'entity_'}${
              n.entity_type
            }`,
          ),
        })),
        sortByLabel,
        R.map((n) => n.label),
      )(this.graphData.nodes);
      const allMarkedBy = R.pipe(
        R.map((n) => n.markedBy),
        R.flatten,
        R.uniqBy(R.prop('id')),
        sortByDefinition,
      )(R.union(this.graphData.nodes, this.graphData.links));
      const allCreatedBy = R.pipe(
        R.map((n) => n.createdBy),
        R.uniqBy(R.prop('id')),
        sortByName,
      )(R.union(this.graphData.nodes, this.graphData.links));
      if (onlyRefresh) {
        this.setState(
          {
            allStixCoreObjectsTypes,
            allMarkedBy,
            allCreatedBy,
          },
          () => {
            this.saveParameters(false);
            resolve(true);
          },
        );
      } else {
        this.setState(
          {
            allStixCoreObjectsTypes,
            allMarkedBy,
            allCreatedBy,
            stixCoreObjectsTypes: allStixCoreObjectsTypes,
            markedBy: allMarkedBy.map((n) => n.id),
            createdBy: allCreatedBy.map((n) => n.id),
            keyword: '',
          },
          () => {
            this.saveParameters(false);
            resolve(true);
          },
        );
      }
    });
  }

  handleZoomToFit(adjust = false) {
    if (adjust === true) {
      const container = document.getElementById('container');
      const { offsetWidth, offsetHeight } = container;
      this.setState({ width: offsetWidth, height: offsetHeight }, () => {
        this.graph.current.zoomToFit(400, 150);
      });
    } else {
      this.graph.current.zoomToFit(400, 150);
    }
  }

  onZoom() {
    this.zoomed += 1;
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
    const { prevClick } = this.state;
    const now = new Date();
    if (event.ctrlKey || event.shiftKey || event.altKey) {
      if (this.selectedNodes.has(node)) {
        this.selectedNodes.delete(node);
      } else {
        this.selectedNodes.add(node);
      }
    } else {
      if (
        prevClick
        && prevClick.node === node
        && now - prevClick.time < DBL_CLICK_TIMEOUT
      ) {
        this.selectedNodes.clear();
        this.selectedLinks.clear();
        this.selectedNodes.add(node);
        this.setState({
          prevClick: null,
          numberOfSelectedNodes: this.selectedNodes.size,
          numberOfSelectedLinks: this.selectedLinks.size,
        });
        return this.handleOpenExpandElements();
      }
      const untoggle = this.selectedNodes.has(node) && this.selectedNodes.size === 1;
      this.selectedNodes.clear();
      this.selectedLinks.clear();
      if (!untoggle) this.selectedNodes.add(node);
    }
    return this.setState({
      prevClick: {
        node,
        time: now,
      },
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

  async handleAddEntity(stixCoreObject) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreObject.id)) return;
    this.graphObjects = [...this.graphObjects, stixCoreObject];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    this.setState(
      {
        selectedTimeRangeInterval,
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          selectedTimeRangeInterval,
        ),
      },
      () => {
        setTimeout(() => this.handleZoomToFit(), 1500);
      },
    );
  }

  async handleAddRelation(stixCoreRelationship) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreRelationship.id)) return;
    this.graphObjects = [...this.graphObjects, stixCoreRelationship];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    this.setState(
      {
        selectedTimeRangeInterval,
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          selectedTimeRangeInterval,
        ),
      },
      () => {
        commitMutation({
          mutation: investigationGraphRelationsAddMutation,
          variables: {
            id: this.props.workspace.id,
            input: {
              toIds: [stixCoreRelationship.id],
              relationship_type: 'has-reference',
            },
          },
        });
        setTimeout(() => this.handleZoomToFit(), 1500);
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
    const toIds = R.map((n) => n.id, relationshipsToRemove);
    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        toIds,
        relationship_type: 'has-reference',
      },
    });
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
      ),
    });
  }

  async handleDeleteSelected() {
    // Remove selected links
    const selectedLinks = Array.from(this.selectedLinks);
    const selectedLinksIds = R.map((n) => n.id, selectedLinks);
    const toIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, this.selectedLinks),
    );
    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        toIds,
        relationship_type: 'has-reference',
      },
    });
    this.graphObjects = R.filter(
      (n) => !R.includes(n.id, selectedLinksIds),
      this.graphObjects,
    );
    this.selectedLinks.clear();

    // Remove selected nodes
    const selectedNodes = Array.from(this.selectedNodes);
    const selectedNodesIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, selectedNodes),
    );
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
    const relationshipsToIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, relationshipsToRemove),
    );
    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        toIds: relationshipsToIds,
        relationship_type: 'has-reference',
      },
    });
    const nodesToIds = R.filter(
      (n) => n !== undefined,
      R.map((n) => n.id, selectedNodes),
    );
    commitMutation({
      mutation: investigationAddStixCoreObjectsLinesRelationsDeleteMutation,
      variables: {
        id: this.props.workspace.id,
        toIds: nodesToIds,
        relationship_type: 'has-reference',
      },
    });
    this.selectedNodes.clear();
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.workspace.graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
      ),
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
  }

  handleCloseEntityEdition(entityId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreObjectQuery, {
        id: entityId,
      })
        .toPromise()
        .then((data) => {
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
              [],
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  handleCloseRelationEdition(relationId) {
    setTimeout(() => {
      fetchQuery(investigationGraphStixCoreRelationshipQuery, {
        id: relationId,
      })
        .toPromise()
        .then((data) => {
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
              [],
              this.state.selectedTimeRangeInterval,
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
    this.handleToggleDisplayProgress();
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
          elementWithTargetTypes:
            filters.entity_type === 'All' ? null : [filters.entity_type],
          count: parseInt(filters.limit, 10),
        },
      )
        .toPromise()
        .then((data) => {
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
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    if (filters.reset_filters) {
      await this.resetAllFilters();
    } else {
      await this.resetAllFilters(true);
    }
    this.setState(
      {
        selectedTimeRangeInterval,
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          selectedTimeRangeInterval,
        ),
      },
      () => {
        commitMutation({
          mutation: investigationGraphRelationsAddMutation,
          variables: {
            id: this.props.workspace.id,
            input: {
              toIds: newElementsIds,
              relationship_type: 'has-reference',
            },
          },
        });
        setTimeout(() => this.handleZoomToFit(), 1000);
      },
    );
    this.handleToggleDisplayProgress();
  }

  handleResetLayout() {
    this.graphData = buildGraphData(this.graphObjects, {}, this.props.t);
    this.setState(
      {
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          [],
          this.state.selectedTimeRangeInterval,
          this.state.keyword,
        ),
      },
      () => {
        this.handleDragEnd();
        this.forceUpdate();
        this.graph.current.d3ReheatSimulation();
        POSITIONS$.next({ action: 'SavePositions' });
      },
    );
  }

  handleTimeRangeChange(interval) {
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        interval,
        this.state.keyword,
      ),
      selectedTimeRangeInterval: interval,
    });
  }

  handleSearch(keyword) {
    this.setState({
      keyword,
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        this.state.selectedTimeRangeInterval,
        keyword,
      ),
    });
  }

  handleOpenExpandElements() {
    this.setState({ openExpandElements: true });
  }

  handleCloseExpandElements() {
    this.setState({ openExpandElements: false });
  }

  onResetExpandElements() {
    this.handleCloseExpandElements();
  }

  onSubmitExpandElements(values, { resetForm }) {
    this.handleExpandElements(values);
    resetForm();
  }

  render() {
    const { workspace, theme, t } = this.props;
    const {
      mode3D,
      modeFixed,
      modeTree,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      displayProgress,
      displayTimeRange,
      selectedTimeRangeInterval,
      width,
      height,
      openExpandElements,
    } = this.state;
    const graphWidth = width || window.innerWidth - 210;
    const graphHeight = height || window.innerHeight - 180;
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    const timeRangeValues = computeTimeRangeValues(
      timeRangeInterval,
      this.graphObjects,
    );
    return (
      <div>
        <WorkspaceHeader
          workspace={workspace}
          adjust={this.handleZoomToFit.bind(this)}
        />
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={openExpandElements}
          onClose={this.handleCloseExpandElements.bind(this)}
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              entity_type: 'All',
              relationship_type: 'All',
              limit: 100,
              reset_filters: true,
            }}
            onSubmit={this.onSubmitExpandElements.bind(this)}
            onReset={this.onResetExpandElements.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('Expand elements')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="entity_type"
                    label={t('Entity types')}
                    fullWidth={true}
                    containerstyle={{
                      width: '100%',
                    }}
                  >
                    {R.pipe(
                      R.map((n) => ({ key: n, label: t(`entity_${n}`) })),
                      R.sortWith([R.ascend(R.prop('label'))]),
                    )([
                      'All',
                      'Attack-Pattern',
                      'Campaign',
                      'Note',
                      'Observed-Data',
                      'Opinion',
                      'Report',
                      'Course-Of-Action',
                      'Individual',
                      'Organization',
                      'Sector',
                      'Indicator',
                      'Infrastructure',
                      'Intrusion-Set',
                      'City',
                      'Country',
                      'Region',
                      'Position',
                      'Malware',
                      'Threat-Actor',
                      'Tool',
                      'Vulnerability',
                      'Incident',
                      'Label',
                      'Marking-Definition',
                      'External-Reference',
                      'Stix-Cyber-Observable',
                      'Domain-Name',
                      'IPv4-Addr',
                      'IPv6-Addr',
                      'StixFile',
                    ]).map((entityType) => (
                      <MenuItem key={entityType.key} value={entityType.key}>
                        {entityType.label}
                      </MenuItem>
                    ))}
                  </Field>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="relationship_type"
                    label={t('Relationship type')}
                    fullWidth={true}
                    containerstyle={{
                      marginTop: 20,
                      width: '100%',
                    }}
                  >
                    {R.pipe(
                      R.map((n) => ({ key: n, label: t(`relationship_${n}`) })),
                      R.sortWith([R.ascend(R.prop('label'))]),
                    )([
                      'All',
                      'uses',
                      'indicates',
                      'targets',
                      'located-at',
                      'related-to',
                      'communicates-with',
                      'attributed-to',
                      'based-on',
                      'mitigates',
                      'variant-of',
                      'compromises',
                      'delivers',
                      'belongs-to',
                      'amplifies',
                    ]).map((relationshipType) => (
                      <MenuItem
                        key={relationshipType.key}
                        value={relationshipType.key}
                      >
                        {relationshipType.label}
                      </MenuItem>
                    ))}
                  </Field>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="limit"
                    label={t('Limit')}
                    type="number"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="reset_filters"
                    label={t('Reset filters')}
                    containerstyle={{ marginTop: 20 }}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Expand')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
        <InvestigationGraphBar
          displayProgress={displayProgress}
          handleToggle3DMode={this.handleToggle3DMode.bind(this)}
          currentMode3D={mode3D}
          handleToggleTreeMode={this.handleToggleTreeMode.bind(this)}
          currentModeTree={modeTree}
          handleToggleFixedMode={this.handleToggleFixedMode.bind(this)}
          currentModeFixed={modeFixed}
          handleZoomToFit={this.handleZoomToFit.bind(this)}
          handleToggleCreatedBy={this.handleToggleCreateBy.bind(this)}
          handleToggleStixCoreObjectType={this.handleToggleStixCoreObjectType.bind(
            this,
          )}
          handleToggleMarkedBy={this.handleToggleMarkedBy.bind(this)}
          stixCoreObjectsTypes={allStixCoreObjectsTypes}
          currentStixCoreObjectsTypes={stixCoreObjectsTypes}
          markedBy={allMarkedBy}
          currentMarkedBy={markedBy}
          createdBy={allCreatedBy}
          currentCreatedBy={createdBy}
          handleSelectAll={this.handleSelectAll.bind(this)}
          handleSelectByType={this.handleSelectByType.bind(this)}
          workspace={workspace}
          onAdd={this.handleAddEntity.bind(this)}
          onDelete={this.handleDelete.bind(this)}
          onAddRelation={this.handleAddRelation.bind(this)}
          handleOpenExpandElements={this.handleOpenExpandElements.bind(this)}
          handleCloseExpandElements={this.handleOpenExpandElements.bind(this)}
          handleDeleteSelected={this.handleDeleteSelected.bind(this)}
          selectedNodes={Array.from(this.selectedNodes)}
          selectedLinks={Array.from(this.selectedLinks)}
          numberOfSelectedNodes={numberOfSelectedNodes}
          numberOfSelectedLinks={numberOfSelectedLinks}
          handleCloseEntityEdition={this.handleCloseEntityEdition.bind(this)}
          handleCloseRelationEdition={this.handleCloseRelationEdition.bind(
            this,
          )}
          handleResetLayout={this.handleResetLayout.bind(this)}
          displayTimeRange={displayTimeRange}
          handleToggleDisplayTimeRange={this.handleToggleDisplayTimeRange.bind(
            this,
          )}
          timeRangeInterval={timeRangeInterval}
          selectedTimeRangeInterval={selectedTimeRangeInterval}
          handleTimeRangeChange={this.handleTimeRangeChange.bind(this)}
          timeRangeValues={timeRangeValues}
          handleSearch={this.handleSearch.bind(this)}
        />
        {mode3D ? (
          <ForceGraph3D
            ref={this.graph}
            width={graphWidth}
            height={graphHeight}
            backgroundColor={theme.palette.background.default}
            graphData={graphData}
            nodeThreeObjectExtend={true}
            nodeThreeObject={(node) => nodeThreePaint(node, theme.palette.text.primary)
            }
            linkColor={(link) => (this.selectedLinks.has(link)
              ? theme.palette.secondary.main
              : theme.palette.primary.main)
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
                  .forEach((selNode) => ['x', 'y', 'z'].forEach(
                    // eslint-disable-next-line no-param-reassign,no-return-assign
                    (coord) => (selNode[`f${coord}`] = selNode[coord] + translate[coord]),
                  ));
              }
            }}
            onNodeDragEnd={(node) => {
              if (this.selectedNodes.has(node)) {
                // finished moving a selected node
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node) // don't touch node being dragged
                  // eslint-disable-next-line no-shadow
                  .forEach((selNode) => {
                    ['x', 'y'].forEach(
                      // eslint-disable-next-line no-param-reassign,no-return-assign
                      (coord) => (selNode[`f${coord}`] = undefined),
                    );
                    // eslint-disable-next-line no-param-reassign
                    selNode.fx = selNode.x;
                    // eslint-disable-next-line no-param-reassign
                    selNode.fy = selNode.y;
                    // eslint-disable-next-line no-param-reassign
                    selNode.fz = selNode.z;
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
            cooldownTicks={modeFixed ? 0 : undefined}
            dagMode={
              // eslint-disable-next-line no-nested-ternary
              modeTree === 'horizontal'
                ? 'lr'
                : modeTree === 'vertical'
                  ? 'td'
                  : undefined
            }
          />
        ) : (
          <ForceGraph2D
            ref={this.graph}
            width={graphWidth}
            height={graphHeight}
            graphData={graphData}
            onZoom={this.onZoom.bind(this)}
            onZoomEnd={this.handleZoomEnd.bind(this)}
            nodeRelSize={4}
            nodeCanvasObject={(
              node,
              ctx, //
            ) =>
              // eslint-disable-next-line implicit-arrow-linebreak
              nodePaint(node, node.color, ctx, this.selectedNodes.has(node))
            }
            nodePointerAreaPaint={nodeAreaPaint}
            // linkDirectionalParticles={(link) => (this.selectedLinks.has(link) ? 20 : 0)}
            // linkDirectionalParticleWidth={1}
            // linkDirectionalParticleSpeed={() => 0.004}
            linkCanvasObjectMode={() => 'after'}
            linkCanvasObject={(link, ctx) => linkPaint(link, ctx, theme.palette.text.primary)
            }
            linkColor={(link) => (this.selectedLinks.has(link)
              ? theme.palette.secondary.main
              : theme.palette.primary.main)
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
                  .forEach((selNode) => ['x', 'y'].forEach(
                    // eslint-disable-next-line no-param-reassign,no-return-assign
                    (coord) => (selNode[`f${coord}`] = selNode[coord] + translate[coord]),
                  ));
              }
            }}
            onNodeDragEnd={(node) => {
              if (this.selectedNodes.has(node)) {
                // finished moving a selected node
                [...this.selectedNodes]
                  .filter((selNode) => selNode !== node) // don't touch node being dragged
                  // eslint-disable-next-line no-shadow
                  .forEach((selNode) => {
                    ['x', 'y'].forEach(
                      // eslint-disable-next-line no-param-reassign,no-return-assign
                      (coord) => (selNode[`f${coord}`] = undefined),
                    );
                    // eslint-disable-next-line no-param-reassign
                    selNode.fx = selNode.x;
                    // eslint-disable-next-line no-param-reassign
                    selNode.fy = selNode.y;
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
            cooldownTicks={modeFixed ? 0 : undefined}
            dagMode={
              // eslint-disable-next-line no-nested-ternary
              modeTree === 'horizontal'
                ? 'lr'
                : modeTree === 'vertical'
                  ? 'td'
                  : undefined
            }
          />
        )}
      </div>
    );
  }
}

InvestigationGraphComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const InvestigationGraph = createFragmentContainer(
  InvestigationGraphComponent,
  {
    workspace: graphql`
      fragment InvestigationGraph_workspace on Workspace {
        id
        name
        description
        manifest
        graph_data
        tags
        type
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
              }
              ... on CourseOfAction {
                name
              }
              ... on Note {
                attribute_abstract
                content
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
                published
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
              }
              ... on Position {
                name
              }
              ... on City {
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
              }
              ... on StixFile {
                observableName: name
              }
              ... on StixMetaObject {
                created
              }
              ... on Label {
                value
                color
              }
              ... on MarkingDefinition {
                definition
                x_opencti_color
              }
              ... on KillChainPhase {
                kill_chain_name
                phase_name
              }
              ... on ExternalReference {
                url
                source_name
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
              ... on StixMetaRelationship {
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

export default R.compose(inject18n, withRouter, withTheme)(InvestigationGraph);
