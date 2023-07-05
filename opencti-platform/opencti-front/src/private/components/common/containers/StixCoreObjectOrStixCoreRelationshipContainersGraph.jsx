import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createRefetchContainer } from 'react-relay';
import * as R from 'ramda';
import { Subject, timer } from 'rxjs';
import withTheme from '@mui/styles/withTheme';
import { debounce } from 'rxjs/operators';
import { withRouter } from 'react-router-dom';
import ForceGraph3D from 'react-force-graph-3d';
import SpriteText from 'three-spritetext';
import ForceGraph2D from 'react-force-graph-2d';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { FileDownloadOutlined, ViewListOutlined } from '@mui/icons-material';
import { GraphOutline } from 'mdi-material-ui';
import withStyles from '@mui/styles/withStyles';
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
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { stixDomainObjectMutationFieldPatch } from '../stix_domain_objects/StixDomainObjectEditionOverview';
import StixCoreObjectOrStixCoreRelationshipContainersGraphBar from './StixCoreObjectOrStixCoreRelationshipContainersGraphBar';
import EntitiesDetailsRightsBar from '../../../../utils/graph/EntitiesDetailsRightBar';
import { UserContext } from '../../../../utils/hooks/useAuth';

const PARAMETERS$ = new Subject().pipe(debounce(() => timer(2000)));
const POSITIONS$ = new Subject().pipe(debounce(() => timer(2000)));

const ignoredStixCoreObjectsTypes = ['Note', 'Opinion'];

const styles = () => ({
  views: {
    marginTop: -35,
    float: 'right',
  },
});

class StixCoreObjectOrStixCoreRelationshipContainersGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.initialized = false;
    this.zoomed = 0;
    this.graph = React.createRef();
    this.selectedNodes = new Set();
    this.selectedLinks = new Set();
    const { params } = props;
    this.zoom = R.propOr(null, 'zoom', params);
    this.graphObjects = R.map(
      (n) => n.node,
      props.data.containersObjectsOfObject.edges,
    );
    this.graphData = buildGraphData(
      this.graphObjects,
      decodeGraphData(
        props.stixDomainObjectOrStixCoreRelationship.x_opencti_graph_data,
      ),
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
        ignoredStixCoreObjectsTypes,
      ),
      numberOfSelectedNodes: 0,
      numberOfSelectedLinks: 0,
      width: null,
      height: null,
      zoomed: false,
      keyword: '',
      navOpen: localStorage.getItem('navOpen') === 'true',
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
    this.props.saveViewParameters({ zoom: this.zoom, ...this.state });
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
      mutation: stixDomainObjectMutationFieldPatch,
      variables: {
        id: this.props.stixDomainObjectOrStixCoreRelationship.id,
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

  handleToggleTreeMode(modeTree) {
    if (modeTree === 'horizontal') {
      this.setState(
        {
          modeTree: this.state.modeTree === 'horizontal' ? null : 'horizontal',
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
          modeTree: this.state.modeTree === 'vertical' ? null : 'vertical',
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

  handleZoomToFit() {
    this.graph.current.zoomToFit(400, 150);
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
        this.state.keyword,
      ),
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

  render() {
    const {
      handleChangeView,
      theme,
      numberOfElements,
      classes,
      handleToggleExports,
      t,
    } = this.props;
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
      displayTimeRange,
      selectedTimeRangeInterval,
      navOpen,
    } = this.state;
    const timeRangeInterval = computeTimeRangeInterval(this.graphObjects);
    const timeRangeValues = computeTimeRangeValues(
      timeRangeInterval,
      this.graphObjects,
    );
    const selectedEntities = [...this.selectedLinks, ...this.selectedNodes];
    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => {
          const graphWidth = window.innerWidth - (navOpen ? 210 : 70);
          const graphHeight = window.innerHeight - 240 - bannerSettings.bannerHeightNumber * 2;
          return (
            <>
              <div className={classes.views}>
                <div style={{ float: 'right', marginTop: -20 }}>
                  {numberOfElements && (
                    <div style={{ float: 'left', padding: '16px 5px 0 0' }}>
                      <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                      {t('entitie(s)')}
                    </div>
                  )}
                  {(typeof handleChangeView === 'function'
                    || typeof handleToggleExports === 'function') && (
                    <ToggleButtonGroup
                      size="small"
                      color="secondary"
                      value="graph"
                      exclusive={true}
                      onChange={(_, value) => {
                        if (value && value === 'export') {
                          handleToggleExports();
                        } else if (value) {
                          handleChangeView(value);
                        }
                      }}
                      style={{ margin: '7px 0 0 5px' }}
                    >
                      <ToggleButton value="lines" aria-label="lines">
                        <Tooltip title={t('Lines view')}>
                          <ViewListOutlined fontSize="small" color="primary" />
                        </Tooltip>
                      </ToggleButton>
                      <ToggleButton value="graph" aria-label="graph">
                        <Tooltip title={t('Graph view')}>
                          <GraphOutline fontSize="small" />
                        </Tooltip>
                      </ToggleButton>
                      <ToggleButton
                        value="export"
                        aria-label="export"
                        disabled={true}
                      >
                        <Tooltip title={t('Open export panel')}>
                          <FileDownloadOutlined fontSize="small" />
                        </Tooltip>
                      </ToggleButton>
                    </ToggleButtonGroup>
                  )}
                </div>
              </div>
              <div className="clearfix" />
              <StixCoreObjectOrStixCoreRelationshipContainersGraphBar
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
                selectedNodes={Array.from(this.selectedNodes)}
                selectedLinks={Array.from(this.selectedLinks)}
                numberOfSelectedNodes={numberOfSelectedNodes}
                numberOfSelectedLinks={numberOfSelectedLinks}
                handleResetLayout={this.handleResetLayout.bind(this)}
                displayTimeRange={displayTimeRange}
                handleToggleDisplayTimeRange={this.handleToggleDisplayTimeRange.bind(
                  this,
                )}
                timeRangeInterval={timeRangeInterval}
                selectedTimeRangeInterval={selectedTimeRangeInterval}
                handleTimeRangeChange={this.handleTimeRangeChange.bind(this)}
                timeRangeValues={timeRangeValues}
                handleChangeView={handleChangeView.bind(this)}
                handleSearch={this.handleSearch.bind(this)}
                navOpen={navOpen}
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
                  nodeCanvasObject={(node, ctx) => nodePaint(
                    {
                      selected: theme.palette.secondary.main,
                      inferred: theme.palette.warning.main,
                    },
                    node,
                    node.color,
                    ctx,
                    this.selectedNodes.has(node),
                  )
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
            </>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipContainersGraphComponent.propTypes = {
  stixDomainObjectOrStixCoreRelationship: PropTypes.object,
  theme: PropTypes.object,
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  relay: PropTypes.object,
  data: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  saveViewParameters: PropTypes.func,
  handleChangeView: PropTypes.func,
};

export const stixCoreObjectOrStixCoreRelationshipContainersGraphQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipContainersGraphQuery(
    $id: String!
    $types: [String]
    $filters: [ContainersFiltering]
    $search: String
  ) {
    ...StixCoreObjectOrStixCoreRelationshipContainersGraph_data
  }
`;

const StixCoreObjectOrStixCoreRelationshipContainersGraph = createRefetchContainer(
  StixCoreObjectOrStixCoreRelationshipContainersGraphComponent,
  {
    data: graphql`
        fragment StixCoreObjectOrStixCoreRelationshipContainersGraph_data on Query {
          containersObjectsOfObject(
            id: $id
            types: $types
            filters: $filters
            search: $search
          ) {
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
                    edges {
                      node {
                        id
                        definition_type
                        definition
                        x_opencti_order
                        x_opencti_color
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
                    edges {
                      node {
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
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }
      `,
  },
  stixCoreObjectOrStixCoreRelationshipContainersGraphQuery,
);

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipContainersGraph);
