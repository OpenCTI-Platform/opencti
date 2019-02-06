import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  pipe,
  forEach,
  difference,
  values,
  pathOr,
  filter,
  last,
  head,
  includes,
  pluck, indexBy, prop,
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
import { commitMutation, fetchQuery } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityLabelModel from '../../../components/graph_node/EntityLabelModel';
import EntityLinkModel from '../../../components/graph_node/EntityLinkModel';
import { distributeElements } from '../../../utils/DagreHelper';
import { serializeGraph } from '../../../utils/GraphHelper';
import { workspaceMutationFieldPatch } from './WorkspaceEditionOverview';
import WorkspaceAddObjectRefs from './WorkspaceAddObjectRefs';
import {
  workspaceMutationRelationAdd,
  workspaceMutationRelationDelete,
} from './WorkspaceAddObjectRefsLines';
import StixRelationCreation from '../stix_relation/StixRelationCreation';
import StixRelationEdition from '../stix_relation/StixRelationEdition';

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
    zIndex: 3000,
    bottom: 13,
  },
});

export const workspaceGraphQuery = graphql`
    query WorkspaceGraphQuery($id: String!) {
        workspace(id: $id) {
            ...WorkspaceGraph_workspace
        }
    }
`;

const workspaceGraphResolveRelationsQuery = graphql`
    query WorkspaceGraphResolveRelationsQuery(
    $fromId: String
    $first: Int
    $inferred: Boolean
    ) {
        stixRelations(fromId: $fromId, first: $first, inferred: $inferred) {
            edges {
                node {
                    id
                    relationship_type
                    first_seen
                    last_seen
                    inferred
                    from {
                        id
                    }
                    to {
                        id
                    }
                }
            }
        }
    }
`;

export const workspaceGraphMutationRelationsAdd = graphql`
    mutation WorkspaceGraphRelationsAddMutation(
    $id: ID!
    $input: RelationsAddInput!
    ) {
        workspaceEdit(id: $id) {
            relationsAdd(input: $input) {
                ...WorkspaceGraph_workspace
            }
        }
    }
`;

const GRAPHER$ = new Subject().pipe(debounce(() => timer(1000)));

class WorkspaceGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openCreateRelation: false,
      createRelationFrom: null,
      createRelationTo: null,
      openEditRelation: false,
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
    const added = difference(
      this.props.workspace.objectRefs.edges,
      prevProps.workspace.objectRefs.edges,
    );
    const removed = difference(
      prevProps.workspace.objectRefs.edges,
      this.props.workspace.objectRefs.edges,
    );
    // if a node has been added, add in graph
    if (added.length > 0) {
      const model = this.props.engine.getDiagramModel();
      const newNodes = map(
        n => new EntityNodeModel({
          id: n.node.id,
          relationId: n.relation.id,
          name: n.node.name,
          type: n.node.type,
        }),
        added,
      );
      forEach((n) => {
        n.addListener({ selectionChanged: this.handleSelection.bind(this) });
        model.addNode(n);
      }, newNodes);
      this.props.engine.repaintCanvas();
    }
    // if a node has been removed, remove in graph
    if (removed.length > 0) {
      const model = this.props.engine.getDiagramModel();
      const removedIds = map(n => n.node.id, removed);
      forEach((n) => {
        if (removedIds.includes(n.extras.id)) {
          n.remove();
        }
      }, values(model.getNodes()));
      this.props.engine.repaintCanvas();
    }

    if (this.props.workspace.graph_data !== prevProps.workspace.graph_data) {
      this.updateView();
    }
    if (this.props.inferred !== prevProps.inferred) {
      this.resolveCurrentNodesLinks();
    }
  }

  initialize() {
    const model = new DiagramModel();
    // prepare nodes
    const nodes = this.props.workspace.objectRefs.edges;

    // decode graph data if any
    let graphData = {};
    if (
      Array.isArray(this.props.workspace.graph_data)
      && head(this.props.workspace.graph_data).length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(head(this.props.workspace.graph_data), 'base64').toString(
          'ascii',
        ),
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

    // add nodes
    forEach((n) => {
      const newNode = new EntityNodeModel({
        id: n.node.id,
        relationId: n.relation.id,
        name: n.node.name,
        type: n.node.type,
      });
      newNode.addListener({
        selectionChanged: this.handleSelection.bind(this),
      });
      const position = pathOr(
        null,
        ['nodes', n.node.id, 'position'],
        graphData,
      );
      if (position && position.x !== undefined && position.y !== undefined) {
        newNode.setPosition(position.x, position.y);
      }
      model.addNode(newNode);
    }, nodes);

    // add listeners
    model.addListener({
      nodesUpdated: this.handleNodeChanges.bind(this),
      linksUpdated: this.handleLinksChange.bind(this),
      zoomUpdated: this.handleSaveGraph.bind(this),
    });
    this.props.engine.setDiagramModel(model);
    this.props.engine.repaintCanvas();
    this.resolveCurrentNodesLinks();
  }

  async resolveCurrentNodesLinks() {
    const model = this.props.engine.getDiagramModel();
    forEach((l) => { l.remove(); }, values(model.getLinks()));

    const nodes = model.getNodes();
    const nodesObject = pipe(
      values,
      map(n => ({ id: n.extras.id, nodeId: n.id })),
      indexBy(prop('id')),
    )(nodes);
    const createdRelations = [];
    const relationsPairs = {};
    for (const n of values(nodes)) {
      await fetchQuery(workspaceGraphResolveRelationsQuery, {
        inferred: this.props.inferred,
        fromId: n.extras.id,
        first: 200,
      }).then((data) => {
        if (data && data.stixRelations) {
          forEach((l) => {
            if (nodesObject[l.node.from.id] && nodesObject[l.node.to.id]) {
              if (!includes(l.node.id, createdRelations)) {
                const fromPort = nodesObject[l.node.from.id] ? model.getNode(nodesObject[l.node.from.id].nodeId).getPort('main') : null;
                const toPort = nodesObject[l.node.to.id] ? model.getNode(nodesObject[l.node.to.id].nodeId).getPort('main') : null;
                if (relationsPairs[`${fromPort.id}-${toPort.id}`]) {
                  const existingLink = model.getLink(relationsPairs[`${fromPort.id}-${toPort.id}`]);
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
                  relationsPairs[`${fromPort.id}-${toPort.id}`] = newLink.id;
                  this.props.engine.repaintCanvas();
                }
              }
            }
          }, data.stixRelations.edges);
          this.props.engine.repaintCanvas();
          this.forceUpdate();
        }
      });
    }
  }

  updateView() {
    const model = this.props.engine.getDiagramModel();

    // decode graph data if any
    let graphData = {};
    if (
      Array.isArray(this.props.workspace.graph_data)
      && head(this.props.workspace.graph_data).length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(head(this.props.workspace.graph_data), 'base64').toString(
          'ascii',
        ),
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
    const model = this.props.engine.getDiagramModel();
    const graphData = serializeGraph(model);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: { key: 'graph_data', value: graphData },
      },
    });
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

  handleNodeChanges(event) {
    if (event.node !== undefined) {
      const { node } = event;
      if (event.isCreated === false) {
        // handle node deletion
        commitMutation({
          mutation: workspaceMutationRelationDelete,
          variables: {
            id: this.props.workspace.id,
            relationId: node.extras.relationId,
          },
        });
        this.handleSaveGraph();
      }
    }
    return true;
  }

  handleLinksChange(event) {
    if (event.isCreated === true) {
      // handle link creation
      event.link.addListener({
        targetPortChanged: this.handleLinkCreation.bind(this),
      });
    }
    return true;
  }

  handleLinkCreation(event) {
    const model = this.props.engine.getDiagramModel();
    const currentLinks = model.getLinks();
    const currentLinksPairs = map(
      n => ({
        source: n.sourcePort.id,
        target: pathOr(null, ['targetPort', 'id'], n),
      }),
      values(currentLinks),
    );
    if (event.port !== undefined) {
      // ensure that the links are not circular on the same element
      const link = last(values(event.port.links));
      const linkPair = {
        source: link.sourcePort.id,
        target: pathOr(null, ['targetPort', 'id'], link),
      };
      const filteredCurrentLinks = filter(
        n => (n.source === linkPair.source && n.target === linkPair.target)
          || (n.source === linkPair.target && n.target === linkPair.source),
        currentLinksPairs,
      );
      if (link.targetPort === null || link.sourcePort === link.targetPort) {
        link.remove();
      } else if (filteredCurrentLinks.length === 1) {
        link.addListener({ selectionChanged: this.handleSelection.bind(this) });
        this.setState({
          openCreateRelation: true,
          createRelationFrom: link.sourcePort.parent.extras,
          createRelationTo: link.targetPort.parent.extras,
          currentLink: link,
        });
      }
    }
    return true;
  }

  handleSelection(event) {
    if (event.isSelected === true && event.openEdit === true) {
      if (event.entity instanceof EntityLinkModel) {
        this.setState({
          openEditRelation: true,
          editRelationId: event.entity.extras.relation.id,
          currentLink: event.entity,
        });
      }
    }
    if (event.isSelected === true && event.expand === true) {
      fetchQuery(workspaceGraphResolveRelationsQuery, {
        inferred: this.props.inferred,
        fromId: event.entity.extras.id,
        first: 30,
      }).then((data) => {
        if (data && data.stixRelations) {
          // prepare actual nodes & relations
          const nodes = this.props.workspace.objectRefs.edges;
          const nodesIds = pipe(
            map(n => n.node),
            pluck('id'),
          )(nodes);
          // check added nodes
          const objectsToAdd = [];
          forEach((n) => {
            if (!includes(n.node.to.id, nodesIds)) {
              objectsToAdd.push(n.node.to.id);
            }
          }, data.stixRelations.edges);
          const input = {
            fromRole: 'knowledge_aggregation',
            toIds: objectsToAdd,
            toRole: 'so',
            through: 'object_refs',
          };
          commitMutation({
            mutation: workspaceGraphMutationRelationsAdd,
            variables: {
              id: this.props.workspace.id,
              input,
            },
            onCompleted: () => {
              this.initialize();
            },
          });
        }
      });
    }
    return true;
  }

  handleCloseRelationCreation() {
    const model = this.props.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    linkObject.remove();
    this.setState({
      openCreateRelation: false,
      createRelationFrom: null,
      createRelationTo: null,
      currentLink: null,
    });
  }

  handleResultRelationCreation(result) {
    const model = this.props.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    const label = new EntityLabelModel();
    label.setExtras([
      {
        id: result.id,
        relationship_type: result.relationship_type,
        first_seen: result.first_seen,
        last_seen: result.last_seen,
      },
    ]);
    linkObject.addLabel(label);
    const input = {
      fromRole: 'so',
      toId: this.props.workspace.id,
      toRole: 'knowledge_aggregation',
      through: 'object_refs',
    };
    commitMutation({
      mutation: workspaceMutationRelationAdd,
      variables: {
        id: result.id,
        input,
      },
      onCompleted(data) {
        linkObject.setExtras({
          relation: result,
          objectRefId: data.workspaceEdit.relationAdd.relation.id,
        });
      },
    });
    this.setState({
      openCreateRelation: false,
      createRelationFrom: null,
      createRelationTo: null,
      currentLink: null,
    });
    this.handleSaveGraph();
  }

  handleCloseRelationEdition() {
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
    });
  }

  handleDeleteRelation() {
    return true;
  }

  autoDistribute() {
    const model = this.props.engine.getDiagramModel();
    const serialized = model.serializeDiagram();
    const distributedSerializedDiagram = distributeElements(serialized);
    const distributedDeSerializedModel = new DiagramModel();
    distributedDeSerializedModel.deSerializeDiagram(
      distributedSerializedDiagram,
      this.props.engine,
    );
    this.props.engine.setDiagramModel(distributedDeSerializedModel);
    this.props.engine.repaintCanvas();
  }

  distribute() {
    this.autoDistribute();
    this.handleSaveGraph();
  }

  zoomToFit() {
    this.props.engine.zoomToFit();
    this.handleSaveGraph();
  }

  render() {
    const { classes, engine, workspace } = this.props;
    const {
      openCreateRelation,
      createRelationFrom,
      createRelationTo,
      openEditRelation,
      editRelationId,
    } = this.state;
    return (
      <div className={classes.container}>
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.zoomToFit.bind(this)}
          style={{ left: 90 }}
        >
          <AspectRatio/>
        </IconButton>
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.distribute.bind(this)}
          style={{ left: 150 }}
        >
          <AutoFix/>
        </IconButton>
        <DiagramWidget
          className={classes.canvas}
          diagramEngine={engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleMovesChange.bind(this)}
        />
        <WorkspaceAddObjectRefs
          workspaceId={workspace.id}
          workspaceObjectRefs={workspace.objectRefs.edges}
        />
        <StixRelationCreation
          open={openCreateRelation}
          from={createRelationFrom}
          to={createRelationTo}
          handleClose={this.handleCloseRelationCreation.bind(this)}
          handleResult={this.handleResultRelationCreation.bind(this)}
        />
        <StixRelationEdition
          open={openEditRelation}
          stixRelationId={editRelationId}
          variant='noGraph'
          handleClose={this.handleCloseRelationEdition.bind(this)}
          handleDelete={this.handleDeleteRelation.bind(this)}
        />
      </div>
    );
  }
}

WorkspaceGraphComponent.propTypes = {
  workspace: PropTypes.object,
  inferred: PropTypes.bool,
  engine: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const WorkspaceGraph = createFragmentContainer(WorkspaceGraphComponent, {
  workspace: graphql`
      fragment WorkspaceGraph_workspace on Workspace {
          id
          name
          graph_data
          objectRefs {
              edges {
                  node {
                      id
                      type
                      name
                      description
                  }
                  relation {
                      id
                  }
              }
          }
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(WorkspaceGraph);
