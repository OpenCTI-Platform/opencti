import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import SpriteText from 'three-spritetext';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { createFragmentContainer, graphql } from 'react-relay';
import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import withTheme from '@mui/styles/withTheme';
import RectangleSelection from 'react-rectangle-selection';
import {
  knowledgeGraphQueryCheckObjectQuery,
  knowledgeGraphQueryStixObjectDeleteMutation,
  knowledgeGraphQueryStixRelationshipDeleteMutation,
  knowledgeGraphStixCoreObjectQuery,
  knowledgeGraphStixRelationshipQuery,
} from '../../common/containers/KnowledgeGraphQuery';
import inject18n from '../../../../components/i18n';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
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
import { getSecondaryRepresentative, getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import GroupingKnowledgeGraphBar from './GroupingKnowledgeGraphBar';
import { groupingMutationFieldPatch } from './GroupingEditionOverview';
import { groupingKnowledgeGraphMutationRelationDeleteMutation, groupingKnowledgeGraphtMutationRelationAddMutation } from './GroupingKnowledgeGraphQuery';
import ContainerHeader from '../../common/containers/ContainerHeader';
import GroupingPopover from './GroupingPopover';
import EntitiesDetailsRightsBar from '../../../../utils/graph/EntitiesDetailsRightBar';
import LassoSelection from '../../../../utils/graph/LassoSelection';
import { hexToRGB } from '../../../../utils/Colors';
import { UserContext } from '../../../../utils/hooks/useAuth';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import { isNotEmptyField } from '../../../../utils/utils';
import RelationSelection from '../../../../utils/graph/RelationSelection';
import withRouter from '../../../../utils/compat-router/withRouter';
import { containerTypes } from '../../../../utils/hooks/useAttributes';

const ignoredStixCoreObjectsTypes = ['Note', 'Opinion'];

const PARAMETERS$ = new Subject().pipe(debounce(() => timer(2000)));
const POSITIONS$ = new Subject().pipe(debounce(() => timer(2000)));

export const groupingKnowledgeGraphQuery = graphql`
  query GroupingKnowledgeGraphQuery($id: String!) {
    grouping(id: $id) {
      ...GroupingKnowledgeGraph_grouping
    }
  }
`;

class GroupingKnowledgeGraphComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `grouping-${props.grouping.id}-knowledge`;
    super(props);
    this.initialized = false;
    this.zoomed = 0;
    this.graph = React.createRef();
    this.selectedNodes = new Set();
    this.selectedLinks = new Set();
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.zoom = R.propOr(null, 'zoom', params);
    this.graphObjects = R.map((n) => n.node, props.grouping.objects.edges);
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(props.grouping.x_opencti_graph_data),
      props.t,
    );
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const sortByDefinition = R.sortBy(
      R.compose(R.toLower, R.prop('definition')),
    );
    const sortByName = R.sortBy(R.compose(R.toLower, R.prop('name')));
    const allStixCoreObjectsTypes = R.pipe(
      R.map((n) => R.assoc(
        'tlabel',
        props.t(
          `${n.relationship_type ? 'relationship_' : 'entity_'}${
            n.entity_type
          }`,
        ),
        n,
      )),
      sortByLabel,
      R.map((n) => n.entity_type),
      R.uniq,
    )(this.graphData.nodes);
    const nodesAndLinks = [...this.graphData.nodes, ...this.graphData.links];
    const allMarkedBy = R.pipe(
      R.map((n) => n.markedBy),
      R.flatten,
      R.uniqBy(R.prop('id')),
      sortByDefinition,
    )(nodesAndLinks);
    const allCreatedBy = R.pipe(
      R.map((n) => n.createdBy),
      R.uniqBy(R.prop('id')),
      sortByName,
    )(nodesAndLinks);
    const stixCoreObjectsTypes = R.propOr([], 'stixCoreObjectsTypes', params);
    const markedBy = R.propOr([], 'objectMarking', params);
    const createdBy = R.propOr([], 'createdBy', params);
    const graphWithFilters = applyFilters(
      this.graphData,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      ignoredStixCoreObjectsTypes,
    );
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    this.state = {
      mode3D: R.propOr(false, 'mode3D', params),
      selectRectangleModeFree: R.propOr(
        false,
        'selectRectangleModeFree',
        params,
      ),
      selectModeFree: params.selectModeFree ?? false,
      selectModeFreeReady: false,
      modeFixed: R.propOr(false, 'modeFixed', params),
      modeTree: R.propOr('', 'modeTree', params),
      displayTimeRange: R.propOr(false, 'displayTimeRange', params),
      rectSelected: {
        origin: [0, 0],
        target: [0, 0],
        shiftKey: false,
        altKey: false,
      },
      selectedTimeRangeInterval: timeRangeInterval,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData: graphWithFilters,
      numberOfSelectedNodes: 0,
      numberOfSelectedLinks: 0,
      width: null,
      height: null,
      zoomed: false,
      keyword: '',
      navOpen: localStorage.getItem('navOpen') === 'true',
      openCreatedRelation: false,
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
      const currentCanvas = document.getElementsByTagName('canvas')[0];
      if (!this.canvas) {
        this.canvas = currentCanvas;
      }
    }
  }

  componentDidMount() {
    this.subscription1 = PARAMETERS$.subscribe({
      next: () => this.saveParameters(),
    });
    this.subscription2 = POSITIONS$.subscribe({
      next: () => this.savePositions(),
    });
    this.subscription3 = MESSAGING$.toggleNav.subscribe({
      next: () => this.setState({ navOpen: localStorage.getItem('navOpen') === 'true' }),
    });
    this.initialize();
  }

  componentWillUnmount() {
    this.subscription1.unsubscribe();
    this.subscription2.unsubscribe();
    this.subscription3.unsubscribe();
  }

  saveParameters(refreshGraphData = false) {
    const LOCAL_STORAGE_KEY = `grouping-${this.props.grouping.id}-knowledge`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      { zoom: this.zoom, ...this.state },
    );
    if (refreshGraphData) {
      this.setState({
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          ignoredStixCoreObjectsTypes,
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
      R.map(
        (n) => ({ id: n.id, x: n.fx, y: n.fy }),
        this.state.graphData.nodes,
      ),
    );
    const positions = R.mergeLeft(newPositions, initialPositions);
    commitMutation({
      mutation: groupingMutationFieldPatch,
      variables: {
        id: this.props.grouping.id,
        input: {
          key: 'x_opencti_graph_data',
          value: encodeGraphData(positions),
        },
      },
    });
  }

  handleToggle3DMode() {
    this.setState({ mode3D: !this.state.mode3D }, () => this.saveParameters());
  }

  handleToggleRectangleSelectModeFree() {
    this.setState(
      {
        selectRectangleModeFree: !this.state.selectRectangleModeFree,
        selectModeFree: false,
      },
      () => {
        this.saveParameters();
      },
    );
  }

  handleToggleSelectModeFree() {
    this.setState(
      {
        selectModeFree: !this.state.selectModeFree,
        selectRectangleModeFree: false,
      },
      () => {
        this.saveParameters();
      },
    );
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

  resetAllFilters() {
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
      this.setState(
        {
          allStixCoreObjectsTypes,
          allMarkedBy,
          allCreatedBy,
          stixCoreObjectsTypes: [],
          markedBy: [],
          createdBy: [],
          keyword: '',
        },
        () => {
          this.saveParameters(true);
          resolve(true);
        },
      );
    });
  }

  handleZoomToFit(adjust = false) {
    let px = 50;
    if (this.graphData.nodes.length === 1) {
      px = 300;
    } else if (this.graphData.nodes.length < 4) {
      px = 200;
    } else if (this.graphData.nodes.length < 8) {
      px = 100;
    }
    if (adjust) {
      const container = document.getElementById('container');
      const { offsetWidth, offsetHeight } = container;
      this.setState({ width: offsetWidth, height: offsetHeight }, () => {
        this.graph.current.zoomToFit(400, px);
      });
    } else {
      this.graph.current.zoomToFit(400, px);
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

  async handleAddEntity(stixCoreObject) {
    if (R.map((n) => n.id, this.graphObjects).includes(stixCoreObject.id)) return;
    this.graphObjects = [...this.graphObjects, stixCoreObject];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.grouping.graph_data),
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
          ignoredStixCoreObjectsTypes,
          selectedTimeRangeInterval,
        ),
      },
      () => {
        setTimeout(() => this.handleZoomToFit(), 1500);
      },
    );
  }

  async handleAddRelation(stixCoreRelationship) {
    const input = {
      toId: stixCoreRelationship.id,
      relationship_type: 'object',
    };
    commitMutation({
      mutation: groupingKnowledgeGraphtMutationRelationAddMutation,
      variables: {
        id: this.props.grouping.id,
        input,
      },
      onCompleted: async () => {
        this.graphObjects = [...this.graphObjects, stixCoreRelationship];
        this.graphData = buildGraphData(
          this.graphObjects,
          decodeGraphData(this.props.grouping.x_opencti_graph_data),
          this.props.t,
        );
        await this.resetAllFilters();
        const selectedTimeRangeInterval = computeTimeRangeInterval(
          this.graphObjects,
        );
        this.setState({
          selectedTimeRangeInterval,
          graphData: applyFilters(
            this.graphData,
            this.state.stixCoreObjectsTypes,
            this.state.markedBy,
            this.state.createdBy,
            ignoredStixCoreObjectsTypes,
            selectedTimeRangeInterval,
          ),
        });
      },
    });
  }

  async handleDelete(stixCoreObject) {
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
      decodeGraphData(this.props.grouping.x_opencti_graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    R.forEach((n) => {
      commitMutation({
        mutation: groupingKnowledgeGraphMutationRelationDeleteMutation,
        variables: {
          id: this.props.grouping.id,
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
        ignoredStixCoreObjectsTypes,
        this.state.selectedTimeRangeInterval,
      ),
    });
  }

  async handleDeleteSelected(deleteObject = false, commitMessage = '', references = [], setSubmitting = null, resetForm = null) {
    const checkedContainerTypes = containerTypes.filter((type) => !ignoredStixCoreObjectsTypes.includes(type)); // containers checked when cascade delete

    // Remove selected links
    const selectedLinks = Array.from(this.selectedLinks);
    const selectedLinksIds = R.map((n) => n.id, selectedLinks);
    R.forEach((n) => {
      fetchQuery(knowledgeGraphQueryCheckObjectQuery, {
        id: n.id,
        entityTypes: checkedContainerTypes,
      })
        .toPromise()
        .then(async (data) => {
          if (
            deleteObject
            && !data.stixObjectOrStixRelationship.is_inferred
            && data.stixObjectOrStixRelationship.containers.edges.length === 1
          ) {
            commitMutation({
              mutation:
                knowledgeGraphQueryStixRelationshipDeleteMutation,
              variables: {
                id: n.id,
              },
              setSubmitting,
            });
          } else {
            commitMutation({
              mutation: groupingKnowledgeGraphMutationRelationDeleteMutation,
              variables: {
                id: this.props.grouping.id,
                toId: n.id,
                relationship_type: 'object',
                commitMessage,
                references,
              },
              setSubmitting,
            });
          }
        });
    }, this.selectedLinks);
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
        mutation: groupingKnowledgeGraphMutationRelationDeleteMutation,
        variables: {
          id: this.props.grouping.id,
          toId: n.id,
          relationship_type: 'object',
          commitMessage,
          references,
        },
        setSubmitting,
      });
    }, relationshipsToRemove);
    R.forEach((n) => {
      fetchQuery(knowledgeGraphQueryCheckObjectQuery, {
        id: n.id,
        entityTypes: checkedContainerTypes,
      })
        .toPromise()
        .then(async (data) => {
          if (
            deleteObject
            && !data.stixObjectOrStixRelationship.is_inferred
            && data.stixObjectOrStixRelationship.containers.edges.length === 1
          ) {
            commitMutation({
              mutation: knowledgeGraphQueryStixObjectDeleteMutation,
              variables: {
                id: n.id,
              },
              setSubmitting,
            });
          } else {
            commitMutation({
              mutation: groupingKnowledgeGraphMutationRelationDeleteMutation,
              variables: {
                id: this.props.grouping.id,
                toId: n.id,
                relationship_type: 'object',
                commitMessage,
                references,
              },
              setSubmitting,
            });
          }
        });
    }, selectedNodes);
    this.selectedNodes.clear();
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.grouping.x_opencti_graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    this.setState({
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        ignoredStixCoreObjectsTypes,
        this.state.selectedTimeRangeInterval,
      ),
      numberOfSelectedNodes: this.selectedNodes.size,
      numberOfSelectedLinks: this.selectedLinks.size,
    });
    if (setSubmitting) setSubmitting(false);
    if (resetForm) resetForm(true);
  }

  handleCloseEntityEdition(entityId) {
    setTimeout(() => {
      fetchQuery(knowledgeGraphStixCoreObjectQuery, {
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
            decodeGraphData(this.props.grouping.x_opencti_graph_data),
            this.props.t,
          );
          this.setState({
            graphData: applyFilters(
              this.graphData,
              this.state.stixCoreObjectsTypes,
              this.state.markedBy,
              this.state.createdBy,
              ignoredStixCoreObjectsTypes,
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  handleCloseRelationEdition(relationId) {
    setTimeout(() => {
      fetchQuery(knowledgeGraphStixRelationshipQuery, {
        id: relationId,
      })
        .toPromise()
        .then((data) => {
          const { stixRelationship } = data;
          this.graphObjects = R.map(
            (n) => (n.id === stixRelationship.id ? stixRelationship : n),
            this.graphObjects,
          );
          this.graphData = buildGraphData(
            this.graphObjects,
            decodeGraphData(this.props.grouping.x_opencti_graph_data),
            this.props.t,
          );
          this.setState({
            graphData: applyFilters(
              this.graphData,
              this.state.stixCoreObjectsTypes,
              this.state.markedBy,
              this.state.createdBy,
              ignoredStixCoreObjectsTypes,
              this.state.selectedTimeRangeInterval,
            ),
          });
        });
    }, 1500);
  }

  inSelectionRect(n) {
    const graphOrigin = this.graph.current.screen2GraphCoords(
      this.state.rectSelected.origin[0],
      this.state.rectSelected.origin[1],
    );
    const graphTarget = this.graph.current.screen2GraphCoords(
      this.state.rectSelected.target[0],
      this.state.rectSelected.target[1],
    );
    return (
      n.x >= graphOrigin.x
      && n.x <= graphTarget.x
      && n.y >= graphOrigin.y
      && n.y <= graphTarget.y
    );
  }

  handleRectSelectMove(e, coords) {
    if (this.state.selectRectangleModeFree) {
      const { left, top } = this.canvas.getBoundingClientRect();
      this.setState({
        rectSelected: {
          origin: [R.min(coords.origin[0], coords.target[0]) - left, R.min(coords.origin[1], coords.target[1]) - top],
          target: [R.max(coords.origin[0], coords.target[0]) - left, R.max(coords.origin[1], coords.target[1]) - top],
          shiftKey: e.shiftKey,
          altKey: e.altKey,
        },
      });
    }
  }

  handleRectSelectUp() {
    if (
      this.state.selectRectangleModeFree
      && (this.state.rectSelected.origin[0]
        !== this.state.rectSelected.target[0]
        || this.state.rectSelected.origin[1] !== this.state.rectSelected.target[1])
    ) {
      if (
        !this.state.rectSelected.shiftKey
        && !this.state.rectSelected.altKey
      ) {
        this.selectedLinks.clear();
        this.selectedNodes.clear();
      }
      if (this.state.rectSelected.altKey) {
        R.map(
          (n) => this.inSelectionRect(n) && this.selectedNodes.delete(n),
          this.state.graphData.nodes,
        );
      } else {
        R.map(
          (n) => this.inSelectionRect(n) && this.selectedNodes.add(n),
          this.state.graphData.nodes,
        );
      }
      this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
    }
    this.setState({
      rectSelected: {
        origin: [0, 0],
        target: [0, 0],
        shiftKey: false,
        altKey: false,
      },
    });
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

  handleResetLayout() {
    this.graphData = buildGraphData(this.graphObjects, {}, this.props.t);
    this.setState(
      {
        graphData: applyFilters(
          this.graphData,
          this.state.stixCoreObjectsTypes,
          this.state.markedBy,
          this.state.createdBy,
          ignoredStixCoreObjectsTypes,
          this.state.selectedTimeRangeInterval,
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

  async handleApplySuggestion(createdRelationships) {
    this.graphObjects = [...this.graphObjects, ...createdRelationships];
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(this.props.grouping.x_opencti_graph_data),
      this.props.t,
    );
    await this.resetAllFilters();
    const selectedTimeRangeInterval = computeTimeRangeInterval(
      this.graphObjects,
    );
    this.setState({
      selectedTimeRangeInterval,
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        ignoredStixCoreObjectsTypes,
        selectedTimeRangeInterval,
      ),
    });
  }

  handleTimeRangeChange(selectedTimeRangeInterval) {
    this.setState({
      selectedTimeRangeInterval,
      graphData: applyFilters(
        this.graphData,
        this.state.stixCoreObjectsTypes,
        this.state.markedBy,
        this.state.createdBy,
        [],
        selectedTimeRangeInterval,
      ),
    });
  }

  handleSearch(keyword) {
    this.selectedLinks.clear();
    this.selectedNodes.clear();
    if (isNotEmptyField(keyword)) {
      const filterByKeyword = (n) => keyword === ''
        || (getMainRepresentative(n) || '').toLowerCase().indexOf(keyword.toLowerCase())
          !== -1
        || (getSecondaryRepresentative(n) || '')
          .toLowerCase()
          .indexOf(keyword.toLowerCase()) !== -1
        || (n.entity_type || '').toLowerCase().indexOf(keyword.toLowerCase())
          !== -1;
      R.map(
        (n) => filterByKeyword(n) && this.selectedNodes.add(n),
        this.state.graphData.nodes,
      );
      this.setState({ numberOfSelectedNodes: this.selectedNodes.size });
    }
  }

  render() {
    const { grouping, theme, mode, enableReferences } = this.props;
    const {
      mode3D,
      modeFixed,
      modeTree,
      allStixCoreObjectsTypes,
      allMarkedBy,
      allCreatedBy,
      selectRectangleModeFree,
      selectModeFree,
      selectModeFreeReady,
      stixCoreObjectsTypes,
      markedBy,
      createdBy,
      graphData,
      numberOfSelectedNodes,
      numberOfSelectedLinks,
      displayTimeRange,
      selectedTimeRangeInterval,
      width,
      height,
      navOpen,
    } = this.state;
    const selectedEntities = [...this.selectedLinks, ...this.selectedNodes];
    const displayLabels = graphData.links.length < 200;
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    const timeRangeValues = computeTimeRangeValues(
      timeRangeInterval,
      this.graphObjects,
    );

    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => {
          const graphWidth = width || window.innerWidth - (navOpen ? 210 : 70);
          const graphHeight = height
            || window.innerHeight - 235 - bannerSettings.bannerHeightNumber * 2;
          return (
            <>
              <ContainerHeader
                container={grouping}
                PopoverComponent={<GroupingPopover />}
                link={`/dashboard/analyses/groupings/${grouping.id}/knowledge`}
                modes={['graph', 'content', 'correlation', 'matrix']}
                currentMode={mode}
                adjust={this.handleZoomToFit.bind(this)}
                knowledge={true}
                enableSuggestions={true}
                onApplied={this.handleApplySuggestion.bind(this)}
                investigationAddFromContainer={investigationAddFromContainer}
              />
              <GroupingKnowledgeGraphBar
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
                handleToggleRectangleSelectModeFree={this.handleToggleRectangleSelectModeFree.bind(
                  this,
                )}
                handleToggleSelectModeFree={this.handleToggleSelectModeFree.bind(
                  this,
                )}
                stixCoreObjectsTypes={allStixCoreObjectsTypes.filter(
                  (a) => !ignoredStixCoreObjectsTypes.includes(a),
                )}
                currentStixCoreObjectsTypes={stixCoreObjectsTypes}
                currentSelectRectangleModeFree={selectRectangleModeFree}
                currentSelectModeFree={selectModeFree}
                selectModeFreeReady={selectModeFreeReady}
                markedBy={allMarkedBy}
                currentMarkedBy={markedBy}
                createdBy={allCreatedBy}
                currentCreatedBy={createdBy}
                handleSelectAll={this.handleSelectAll.bind(this)}
                handleSelectByType={this.handleSelectByType.bind(this)}
                grouping={grouping}
                onAdd={this.handleAddEntity.bind(this)}
                onDelete={this.handleDelete.bind(this)}
                onAddRelation={this.handleAddRelation.bind(this)}
                handleDeleteSelected={this.handleDeleteSelected.bind(this)}
                selectedNodes={Array.from(this.selectedNodes)}
                selectedLinks={Array.from(this.selectedLinks)}
                numberOfSelectedNodes={numberOfSelectedNodes}
                numberOfSelectedLinks={numberOfSelectedLinks}
                handleCloseEntityEdition={this.handleCloseEntityEdition.bind(
                  this,
                )}
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
                navOpen={navOpen}
                resetAllFilters={this.resetAllFilters.bind(this)}
                openCreatedRelation={this.state.openCreatedRelation}
                handleCloseRelationCreation={() => this.setState({ openCreatedRelation: false })}
                enableReferences={enableReferences}
              />
              {selectedEntities.length > 0 && (
                <EntitiesDetailsRightsBar
                  selectedEntities={selectedEntities}
                  navOpen={navOpen}
                />
              )}
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
                  linkLineDash={[2, 1]}
                  linkWidth={0.2}
                  linkDirectionalArrowLength={3}
                  linkDirectionalArrowRelPos={0.99}
                  linkThreeObjectExtend={true}
                  linkThreeObject={(link) => {
                    if (!displayLabels) return null;
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
                <>
                  <LassoSelection
                    width={graphWidth}
                    height={graphHeight}
                    activated={selectModeFree && selectModeFreeReady}
                    graphDataNodes={graphData.nodes}
                    graph={this.graph}
                    setSelectedNodes={(nodes) => {
                      this.selectedNodes.clear();
                      Array.from(nodes).forEach((n) => this.selectedNodes.add(n));
                      this.setState({ numberOfSelectedNodes: nodes.size });
                    }}
                  />
                  <RelationSelection
                    activated={!(selectModeFree && selectModeFreeReady) && !selectRectangleModeFree}
                    width={graphWidth}
                    height={graphHeight}
                    graphDataNodes={graphData.nodes}
                    graph={this.graph}
                    setSelectedNodes={(nodes) => {
                      this.selectedNodes.clear();
                      Array.from(nodes).forEach((n) => this.selectedNodes.add(n));
                      this.setState({ numberOfSelectedNodes: this.selectedNodes.size, openCreatedRelation: true });
                    }}
                  />
                  <RectangleSelection
                    onSelect={(e, coords) => {
                      this.handleRectSelectMove(e, coords);
                    }}
                    onMouseUp={(e) => {
                      this.handleRectSelectUp(e);
                    }}
                    style={{
                      backgroundColor: hexToRGB(
                        theme.palette.background.accent,
                        0.3,
                      ),
                      borderColor: theme.palette.warning.main,
                    }}
                    disabled={!selectRectangleModeFree}
                  >
                    <ForceGraph2D
                      ref={this.graph}
                      width={graphWidth}
                      height={graphHeight}
                      graphData={graphData}
                      onZoom={this.onZoom.bind(this)}
                      onZoomEnd={this.handleZoomEnd.bind(this)}
                      nodeRelSize={4}
                      enablePanInteraction={
                        !selectRectangleModeFree && !selectModeFree
                      }
                      nodeCanvasObject={(node, ctx) => nodePaint(
                        {
                          selected: theme.palette.secondary.main,
                          inferred: theme.palette.warning.main,
                          disabled: theme.palette.background.paper,
                        },
                        node,
                        node.color,
                        ctx,
                        this.selectedNodes.has(node),
                        node.isNestedInferred,
                        node.disabled,
                      )
                      }
                      nodePointerAreaPaint={nodeAreaPaint}
                      // linkDirectionalParticles={(link) => (this.selectedLinks.has(link) ? 20 : 0)}
                      // linkDirectionalParticleWidth={1}
                      // linkDirectionalParticleSpeed={() => 0.004}
                      linkCanvasObjectMode={() => 'after'}
                      linkCanvasObject={(link, ctx) => (displayLabels
                        ? linkPaint(link, ctx, theme.palette.text.primary)
                        : null)
                      }
                      linkColor={(link) => {
                        if (this.selectedLinks.has(link)) {
                          return theme.palette.secondary.main;
                        }
                        if (link.isNestedInferred) {
                          return theme.palette.warning.main;
                        }
                        if (link.disabled) {
                          return theme.palette.background.paper;
                        }
                        return theme.palette.primary.main;
                      }}
                      linkLineDash={(link) => (link.inferred || link.isNestedInferred ? [2, 1] : null)
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
                      cooldownTicks={modeFixed ? 0 : 100}
                      onEngineStop={() => this.setState({ selectModeFreeReady: true })
                      }
                      dagMode={
                        // eslint-disable-next-line no-nested-ternary
                        modeTree === 'horizontal'
                          ? 'lr'
                          : modeTree === 'vertical'
                            ? 'td'
                            : undefined
                      }
                      dagLevelDistance={50}
                    />
                  </RectangleSelection>
                </>
              )}
            </>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

GroupingKnowledgeGraphComponent.propTypes = {
  grouping: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  mode: PropTypes.string,
  t: PropTypes.func,
};

const GroupingKnowledgeGraph = createFragmentContainer(
  GroupingKnowledgeGraphComponent,
  {
    grouping: graphql`
      fragment GroupingKnowledgeGraph_grouping on Grouping {
        id
        name
        x_opencti_graph_data
        context
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
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              ... on StixDomainObject {
                is_inferred
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
              ... on ObservedData {
                name
              }
              ... on CourseOfAction {
                name
              }
              ... on Note {
                attribute_abstract
                content
              }
              ... on Opinion {
                opinion
              }
              ... on Report {
                name
                published
              }
              ... on Grouping {
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
              ... on MalwareAnalysis {
                result_name
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
                description
                start_time
                stop_time
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
              ... on StixCyberObservable {
                observable_value
              }
              ... on StixFile {
                observableName: name
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
                is_inferred
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
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              ... on StixRefRelationship {
                relationship_type
                start_time
                stop_time
                confidence
                created
                is_inferred
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
                datable
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              ... on StixSightingRelationship {
                relationship_type
                first_seen
                last_seen
                confidence
                created
                is_inferred
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
    `,
  },
);

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
)(GroupingKnowledgeGraph);
