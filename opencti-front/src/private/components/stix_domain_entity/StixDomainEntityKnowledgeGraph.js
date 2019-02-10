import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  pipe,
  forEach,
  append,
  values,
  pathOr,
  head,
  pluck,
  includes,
  indexBy,
  prop,
  uniq,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  DiagramModel,
  DiagramWidget,
  MoveItemsAction,
  MoveCanvasAction,
} from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import { AspectRatio } from '@material-ui/icons';
import { AutoFix } from 'mdi-material-ui';
import { debounce } from 'rxjs/operators/index';
import { Subject, timer } from 'rxjs/index';
import { yearFormat } from '../../../utils/Time';
import { distributeElements } from '../../../utils/DagreHelper';
import { serializeGraph } from '../../../utils/GraphHelper';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityLabelModel from '../../../components/graph_node/EntityLabelModel';
import EntityLinkModel from '../../../components/graph_node/EntityLinkModel';
import { stixDomainEntityMutationFieldPatch } from './StixDomainEntityEditionOverview';
import StixRelationEdition from '../stix_relation/StixRelationEdition';
import StixRelationEditionInferred from '../stix_relation/StixRelationEditionInferred';

const styles = () => ({
  container: {
    position: 'relative',
    overflow: 'hidden',
    margin: 0,
    padding: 0,
  },
  canvas: {
    width: '100%',
    height: '100%',
    minHeight: 'calc(100vh - 170px)',
    margin: 0,
    padding: 0,
  },
  icon: {
    position: 'fixed',
    zIndex: 1001,
    bottom: 13,
  },
});

const GRAPHER$ = new Subject().pipe(debounce(() => timer(1000)));

class StixDomainEntityKnowledgeGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openEditRelation: false,
      openEditRelationInferred: false,
      editRelationId: null,
      currentLink: null,
    };
  }

  componentDidMount() {
    this.initialize();
    this.subscription = GRAPHER$.subscribe({
      next: (message) => {
        if (message.action === 'update') {
          this.saveGraph();
        }
      },
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  componentDidUpdate(prevProps) {
    if (this.props.firstSeenYear !== prevProps.firstSeenYear) {
      const model = this.props.engine.getDiagramModel();
      const links = model.getLinks();
      forEach((l) => {
        if (
          yearFormat(
            pathOr('1970-01-01', ['extras', 'relation', 'first_seen'], l),
          ) === this.props.firstSeenYear
        ) {
          l.setColor('#ff3d00');
        } else {
          l.setColor('#00bcd4');
        }
      }, values(links));
      this.props.engine.repaintCanvas();
    }

    if (
      this.props.stixDomainEntity.graph_data
      !== prevProps.stixDomainEntity.graph_data
    ) {
      this.updateView();
    }
  }

  initialize() {
    const {
      stixDomainEntity,
      stixDomainEntity: { stixRelations },
    } = this.props;
    const model = new DiagramModel();

    // prepare actual nodes & relations
    const nodes = append(
      stixDomainEntity,
      uniq(map(n => n.node.to, stixRelations.edges)),
    );
    const relations = stixRelations.edges;

    // decode graph data if any
    let graphData = {};
    if (Array.isArray(stixDomainEntity.graph_data) && head(stixDomainEntity.graph_data).length > 0) {
      graphData = JSON.parse(Buffer.from(head(stixDomainEntity.graph_data), 'base64').toString('ascii'));
    }

    // set offset & zoom
    if (graphData.zoom) {
      model.setZoomLevel(graphData.zoom);
    }
    if (graphData.offsetX) {
      model.setOffsetX(graphData.offsetX);
    }
    if (graphData.offsetY) {
      model.setOffsetY(graphData.offsetY);
    }

    // add nodes
    forEach((n) => {
      const newNode = new EntityNodeModel({
        id: n.id,
        name: n.name,
        type: n.type,
      });
      newNode.addListener({
        selectionChanged: this.handleSelection.bind(this),
      });
      const position = pathOr(null, ['nodes', n.id, 'position'], graphData);
      if (position && position.x !== undefined && position.y !== undefined) {
        newNode.setPosition(position.x, position.y);
      }
      model.addNode(newNode);
    }, nodes);

    // build usables nodes object
    const finalNodes = model.getNodes();
    const finalNodesObject = pipe(
      values,
      map(n => ({ id: n.extras.id, node: n })),
      indexBy(prop('id')),
    )(finalNodes);

    // add relations
    const createdRelations = [];
    forEach((l) => {
      if (!includes(l.id, createdRelations)) {
        const fromPort = finalNodesObject[stixDomainEntity.id]
          ? finalNodesObject[stixDomainEntity.id].node.getPort('main')
          : null;
        const toPort = finalNodesObject[l.node.to.id]
          ? finalNodesObject[l.node.to.id].node.getPort('main')
          : null;
        const toPortLinks = values(toPort.getLinks());
        if (toPortLinks.length === 1) {
          const existingLink = model.getLink(head(toPortLinks));
          const label = head(existingLink.labels);
          const extrasIds = pluck('id', label.extras);
          if (!includes(l.node.id, extrasIds)) {
            label.extras.push({
              id: l.node.id,
              relationship_type: l.node.relationship_type,
              first_seen: l.node.first_seen,
              last_seen: l.node.last_seen,
            });
          }
        } else {
          const newLink = new EntityLinkModel();
          newLink.setExtras({
            relation: l.node,
          });
          newLink.setSourcePort(fromPort);
          newLink.setTargetPort(toPort);
          const label = new EntityLabelModel();
          label.setExtras([
            {
              id: l.node.id,
              relationship_type: l.node.relationship_type,
              first_seen: l.node.first_seen,
              last_seen: l.node.last_seen,
              inferred: l.node.inferred,
            },
          ]);
          newLink.addLabel(label);
          newLink.setInferred(l.node.inferred);
          newLink.addListener({
            selectionChanged: this.handleSelection.bind(this),
          });
          model.addLink(newLink);
          createdRelations.push(l.node.id);
        }
      }
    }, relations);

    // add listeners
    model.addListener({
      linksUpdated: this.handleLinksChange.bind(this),
      zoomUpdated: this.handleSaveGraph.bind(this),
    });
    this.props.engine.setDiagramModel(model);
    this.props.engine.repaintCanvas();
  }

  updateView() {
    const model = this.props.engine.getDiagramModel();

    // decode graph data if any
    let graphData = {};
    if (
      Array.isArray(this.props.stixDomainEntity.graph_data)
      && head(this.props.stixDomainEntity.graph_data).length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(
          head(this.props.stixDomainEntity.graph_data),
          'base64',
        ).toString('ascii'),
      );
    }

    // set offset & zoom
    if (graphData.zoom) {
      model.setZoomLevel(graphData.zoom);
    }
    if (graphData.offsetX) {
      model.setOffsetX(graphData.offsetX);
    }
    if (graphData.offsetY) {
      model.setOffsetY(graphData.offsetY);
    }

    // set nodes positions
    const nodes = model.getNodes();
    forEach((n) => {
      const position = pathOr(
        null,
        ['nodes', n.extras.id, 'position'],
        graphData,
      );
      if (position && position.x && position.y) {
        n.setPosition(position.x, position.y);
      }
    })(values(nodes));
    this.props.engine.repaintCanvas();
  }

  saveGraph() {
    if (this.props.isSavable()) {
      const model = this.props.engine.getDiagramModel();
      const graphData = serializeGraph(model);
      commitMutation({
        mutation: stixDomainEntityMutationFieldPatch,
        variables: {
          id: this.props.stixDomainEntity.id,
          input: { key: 'graph_data', value: graphData },
        },
      });
    }
  }

  handleSaveGraph() {
    GRAPHER$.next({ action: 'update' });
  }

  handleMovesChange(event) {
    if (event instanceof MoveItemsAction || event instanceof MoveCanvasAction) {
      // handle drag & drop
      this.handleSaveGraph();
    }
    return true;
  }

  handleLinksChange(event) {
    if (event.isCreated === true) {
      event.link.remove();
    }
    return true;
  }

  handleSelection(event) {
    if (event.isSelected === true && event.openEdit === true) {
      if (event.entity instanceof EntityLinkModel) {
        if (event.inferred) {
          this.setState({
            openEditRelationInferred: true,
            editRelationId: event.entity.extras.relation.id,
            currentLink: event.entity,
          });
        } else {
          this.setState({
            openEditRelation: true,
            editRelationId: event.entity.extras.relation.id,
            currentLink: event.entity,
          });
        }
      }
    }
    return true;
  }

  handleCloseRelationEdition() {
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
    });
  }

  handleCloseRelationEditionInferred() {
    this.setState({
      openEditRelationInferred: false,
      editRelationId: null,
      currentLink: null,
    });
  }

  handleDeleteRelation() {
    return false;
  }

  autoDistribute() {
    const model = this.props.engine.getDiagramModel();
    const serialized = model.serializeDiagram();
    const distributedSerializedDiagram = distributeElements(serialized);
    const distributedDeSerializedModel = new DiagramModel();
    distributedDeSerializedModel.deSerializeDiagram(distributedSerializedDiagram, this.props.engine);
    this.props.engine.setDiagramModel(distributedDeSerializedModel);
    this.props.engine.repaintCanvas();
    this.handleSaveGraph();
  }

  distribute() {
    this.autoDistribute();
  }

  zoomToFit() {
    this.props.engine.zoomToFit();
    this.handleSaveGraph();
  }

  render() {
    const { classes, stixDomainEntity } = this.props;
    const { openEditRelation, openEditRelationInferred, editRelationId } = this.state;
    return (
      <div className={classes.container}>
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.zoomToFit.bind(this)}
          style={{ right: 330 }}
        >
          <AspectRatio/>
        </IconButton>
        <IconButton
          color="primary"
          className={classes.icon}
          style={{ right: 270 }}
        >
          <AutoFix/>
        </IconButton>
        <DiagramWidget
          deleteKeys={[]}
          className={classes.canvas}
          diagramEngine={this.props.engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleMovesChange.bind(this)}
        />
        <StixRelationEdition
          open={openEditRelation}
          stixRelationId={editRelationId}
          stixDomainEntity={stixDomainEntity}
          variant='noGraph'
          handleClose={this.handleCloseRelationEdition.bind(this)}
          handleDelete={this.handleDeleteRelation.bind(this)}
        />
        <StixRelationEditionInferred
          open={openEditRelationInferred}
          stixRelationId={editRelationId}
          stixDomainEntity={stixDomainEntity}
          handleClose={this.handleCloseRelationEditionInferred.bind(this)}
        />
      </div>
    );
  }
}

StixDomainEntityKnowledgeGraphComponent.propTypes = {
  stixDomainEntity: PropTypes.object,
  engine: PropTypes.object,
  firstSeenYear: PropTypes.string,
  isSavable: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainEntityKnowledgeGraph = createFragmentContainer(
  StixDomainEntityKnowledgeGraphComponent,
  {
    stixDomainEntity: graphql`
        fragment StixDomainEntityKnowledgeGraph_stixDomainEntity on StixDomainEntity
        @argumentDefinitions(
            inferred: { type: "Boolean" }
            toTypes: { type: "[String]" }
            firstSeenStart: { type: "DateTime" }
            firstSeenStop: { type: "DateTime" }
            lastSeenStart: { type: "DateTime" }
            lastSeenStop: { type: "DateTime" }
            weights: { type: "[Int]" }
            count: { type: "Int", defaultValue: 50 }
        ) {
            id
            type
            name
            graph_data
            stixRelations(
                inferred: $inferred
                toTypes: $toTypes
                firstSeenStart: $firstSeenStart
                firstSeenStop: $firstSeenStop
                lastSeenStart: $lastSeenStart
                lastSeenStop: $lastSeenStop
                weights: $weights
                first: $count
            ) {
                edges {
                    node {
                        id
                        relationship_type
                        inferred
                        description
                        first_seen
                        last_seen
                        to {
                            id
                            type
                            name
                        }
                    }
                }
            }
        }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKnowledgeGraph);
