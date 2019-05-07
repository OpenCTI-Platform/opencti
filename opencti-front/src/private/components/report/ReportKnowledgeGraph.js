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
  includes,
  indexBy,
  prop,
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
import { debounce } from 'rxjs/operators/index';
import { Subject, timer } from 'rxjs/index';
import { commitMutation, fetchQuery } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityLabelModel from '../../../components/graph_node/EntityLabelModel';
import EntityLinkModel from '../../../components/graph_node/EntityLinkModel';
import { distributeElements } from '../../../utils/DagreHelper';
import { serializeGraph } from '../../../utils/GraphHelper';
import { dateFormat } from '../../../utils/Time';
import { reportMutationFieldPatch } from './ReportEditionOverview';
import ReportAddObjectRefs from './ReportAddObjectRefs';
import {
  reportMutationRelationAdd,
  reportMutationRelationDelete,
} from './ReportAddObjectRefsLines';
import StixRelationCreation from '../stix_relation/StixRelationCreation';
import StixRelationEdition, {
  stixRelationEditionDeleteMutation,
} from '../stix_relation/StixRelationEdition';

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

export const reportKnowledgeGraphQuery = graphql`
  query ReportKnowledgeGraphQuery($id: String!) {
    report(id: $id) {
      ...ReportKnowledgeGraph_report
    }
  }
`;

const reportKnowledgeGraphRelationQuery = graphql`
  query ReportKnowledgeGraphRelationQuery($id: String!) {
    stixRelation(id: $id) {
      id
      first_seen
      last_seen
      relationship_type
    }
  }
`;

const reportKnowledgeGraphCheckRelationQuery = graphql`
  query ReportKnowledgeGraphCheckRelationQuery($id: String!) {
    stixRelation(id: $id) {
      id
      reports {
        edges {
          node {
            id
          }
        }
      }
    }
  }
`;

const GRAPHER$ = new Subject().pipe(debounce(() => timer(1000)));

class ReportKnowledgeGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openCreateRelation: false,
      createRelationFrom: null,
      createRelationTo: null,
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
      lastLinkFirstSeen: null,
      lastLinkLastSeen: null,
    };
    this.diagramContainer = React.createRef();
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
    // Fix Firefox zoom issue
    this.diagramContainer.current.addEventListener('wheel', (event) => {
      if (event.deltaMode === event.DOM_DELTA_LINE) {
        event.stopPropagation();
        const customScroll = new WheelEvent('wheel', {
          bubbles: event.bubbles,
          deltaMode: event.DOM_DELTA_PIXEL,
          clientX: event.clientX,
          clientY: event.clientY,
          deltaX: event.deltaX,
          deltaY: 20 * event.deltaY,
        });
        event.target.dispatchEvent(customScroll);
      }
    });
  }

  componentWillUnmount() {
    this.saveGraph();
    this.subscription.unsubscribe();
  }

  componentDidUpdate(prevProps) {
    const added = difference(
      this.props.report.objectRefs.edges,
      prevProps.report.objectRefs.edges,
    );
    const removed = difference(
      prevProps.report.objectRefs.edges,
      this.props.report.objectRefs.edges,
    );
    // if a node has been added, add in graph
    if (added.length > 0) {
      const model = this.props.engine.getDiagramModel();
      const newNodes = map(
        n => new EntityNodeModel({
          id: n.node.id,
          internalId: n.node.internal_id,
          relationId: n.relation.id,
          name: n.node.name,
          type: n.node.entity_type,
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

    if (this.props.report.graph_data !== prevProps.report.graph_data) {
      this.updateView();
    }
  }

  initialize() {
    const model = new DiagramModel();
    // prepare nodes & relations
    const nodes = this.props.report.objectRefs.edges;
    const relations = this.props.report.relationRefs.edges;

    // decode graph data if any
    let graphData = {};
    if (
      this.props.report.graph_data
      && this.props.report.graph_data.length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(this.props.report.graph_data, 'base64').toString('ascii'),
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
        internalId: n.node.internal_id,
        relationId: n.relation.id,
        name: n.node.name,
        type: n.node.entity_type,
      });
      newNode.addListener({
        selectionChanged: this.handleSelection.bind(this),
      });
      console.log(graphData);
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
      if (
        !includes(l.relation.id, createdRelations)
        && l.node.relationship_type !== 'indicates'
      ) {
        const fromPort = finalNodesObject[l.node.from.id]
          ? finalNodesObject[l.node.from.id].node.getPort('main')
          : null;
        const toPort = finalNodesObject[l.node.to.id]
          ? finalNodesObject[l.node.to.id].node.getPort('main')
          : null;
        if (fromPort === null || toPort === null) {
          return false;
        }
        const newLink = new EntityLinkModel();
        newLink.setExtras({
          relation: l.node,
          objectRefId: l.relation.id,
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
          },
        ]);
        newLink.addLabel(label);
        newLink.addListener({
          selectionChanged: this.handleSelection.bind(this),
        });
        model.addLink(newLink);
        createdRelations.push(l.relation.id);
        return true;
      }
      return false;
    }, relations);

    // add listeners
    model.addListener({
      nodesUpdated: this.handleNodeChanges.bind(this),
      linksUpdated: this.handleLinksChange.bind(this),
    });
    this.props.engine.setDiagramModel(model);
    this.props.engine.repaintCanvas();
  }

  updateView() {
    const model = this.props.engine.getDiagramModel();

    // decode graph data if any
    let graphData = {};
    if (
      this.props.report.graph_data
      && this.props.report.graph_data.length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(this.props.report.graph_data, 'base64').toString('ascii'),
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
      mutation: reportMutationFieldPatch,
      variables: {
        id: this.props.report.id,
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
          mutation: reportMutationRelationDelete,
          variables: {
            id: this.props.report.id,
            relationId: node.extras.relationId,
          },
        });
        this.handleSaveGraph();
      }
    }
    return true;
  }

  handleLinksChange(event) {
    const model = this.props.engine.getDiagramModel();
    const currentLinks = model.getLinks();
    const currentLinksPairs = map(
      n => ({
        source: n.sourcePort.id,
        target: pathOr(null, ['targetPort', 'id'], n),
      }),
      values(currentLinks),
    );
    if (event.isCreated === true) {
      // handle link creation
      event.link.addListener({
        targetPortChanged: this.handleLinkCreation.bind(this),
      });
    } else if (event.link !== undefined) {
      // handle link deletion
      const { link } = event;
      if (link.targetPort !== null && link.sourcePort !== link.targetPort) {
        const linkPair = {
          source: link.sourcePort.id,
          target: pathOr(null, ['targetPort', 'id'], link),
        };
        const filteredCurrentLinks = filter(
          n => (n.source === linkPair.source && n.target === linkPair.target)
            || (n.source === linkPair.target && n.target === linkPair.source),
          currentLinksPairs,
        );
        if (filteredCurrentLinks.length === 0) {
          if (link.extras && link.extras.relation) {
            fetchQuery(reportKnowledgeGraphCheckRelationQuery, {
              id: link.extras.relation.id,
            }).then((data) => {
              if (data.stixRelation.reports.edges.length === 1) {
                commitMutation({
                  mutation: stixRelationEditionDeleteMutation,
                  variables: {
                    id: link.extras.relation.id,
                  },
                });
              }
              commitMutation({
                mutation: reportMutationRelationDelete,
                variables: {
                  id: this.props.report.id,
                  relationId: link.extras.objectRefId,
                },
              });
            });
          }
        }
      }
      this.handleSaveGraph();
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
    this.setState({
      lastLinkFirstSeen: result.first_seen,
      lastLinkLastSeen: result.last_seen,
    });
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
      toId: this.props.report.id,
      toRole: 'knowledge_aggregation',
      through: 'object_refs',
    };
    commitMutation({
      mutation: reportMutationRelationAdd,
      variables: {
        id: result.id,
        input,
      },
      onCompleted(data) {
        linkObject.setExtras({
          relation: result,
          objectRefId: data.reportEdit.relationAdd.relation.id,
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
    const { editRelationId, currentLink } = this.state;
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
    });
    fetchQuery(reportKnowledgeGraphRelationQuery, { id: editRelationId }).then(
      (data) => {
        const { stixRelation } = data;
        const model = this.props.engine.getDiagramModel();
        const linkObject = model.getLink(currentLink);
        const label = new EntityLabelModel();
        label.setExtras([
          {
            id: stixRelation.id,
            relationship_type: stixRelation.relationship_type,
            first_seen: stixRelation.first_seen,
            last_seen: stixRelation.last_seen,
          },
        ]);
        linkObject.setLabel(label);
      },
    );
  }

  handleDeleteRelation() {
    const model = this.props.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    linkObject.remove();
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
    });
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
    const { classes, engine, report } = this.props;
    const {
      openCreateRelation,
      createRelationFrom,
      createRelationTo,
      openEditRelation,
      editRelationId,
      lastLinkFirstSeen,
      lastLinkLastSeen,
    } = this.state;
    return (
      <div className={classes.container} ref={this.diagramContainer}>
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.zoomToFit.bind(this)}
          style={{ left: 90 }}
        >
          <AspectRatio />
        </IconButton>
        <DiagramWidget
          className={classes.canvas}
          deleteKeys={[46]}
          diagramEngine={engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleMovesChange.bind(this)}
        />
        <ReportAddObjectRefs
          reportId={report.id}
          reportObjectRefs={report.objectRefs.edges}
        />
        <StixRelationCreation
          open={openCreateRelation}
          from={createRelationFrom}
          to={createRelationTo}
          firstSeen={lastLinkFirstSeen || dateFormat(report.published)}
          lastSeen={lastLinkLastSeen || dateFormat(report.published)}
          weight={report.source_confidence_level}
          handleClose={this.handleCloseRelationCreation.bind(this)}
          handleResult={this.handleResultRelationCreation.bind(this)}
        />
        <StixRelationEdition
          open={openEditRelation}
          stixRelationId={editRelationId}
          handleClose={this.handleCloseRelationEdition.bind(this)}
          handleDelete={this.handleDeleteRelation.bind(this)}
        />
      </div>
    );
  }
}

ReportKnowledgeGraphComponent.propTypes = {
  report: PropTypes.object,
  engine: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ReportKnowledgeGraph = createFragmentContainer(
  ReportKnowledgeGraphComponent,
  {
    report: graphql`
      fragment ReportKnowledgeGraph_report on Report {
        id
        internal_id
        name
        graph_data
        published
        source_confidence_level
        objectRefs {
          edges {
            node {
              id
              internal_id
              entity_type
              name
              description
              created_at
              updated_at
            }
            relation {
              id
            }
          }
        }
        relationRefs {
          edges {
            node {
              id
              internal_id
              relationship_type
              first_seen
              last_seen
              from {
                id
                internal_id
                entity_type
                name
              }
              to {
                id
                internal_id
                entity_type
                name
              }
            }
            relation {
              id
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
)(ReportKnowledgeGraph);
