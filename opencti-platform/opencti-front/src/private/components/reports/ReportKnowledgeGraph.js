import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  pipe,
  forEach,
  differenceWith,
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
import { GraphOutline } from 'mdi-material-ui';
import { debounce } from 'rxjs/operators/index';
import { Subject, timer } from 'rxjs/index';
import { commitMutation, fetchQuery } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import GlobalLinkModel from '../../../components/graph_node/GlobalLinkModel';
import RelationNodeModel from '../../../components/graph_node/RelationNodeModel';
import distributeElements from '../../../utils/DagreHelper';
import { serializeGraph } from '../../../utils/GraphHelper';
import { dateFormat } from '../../../utils/Time';
import { reportMutationFieldPatch } from './ReportEditionOverview';
import ReportAddObjectRefs from './ReportAddObjectRefs';
import StixRelationCreation from '../common/stix_relations/StixRelationCreation';
import StixDomainEntityEdition from '../common/stix_domain_entities/StixDomainEntityEdition';
import StixRelationEdition, {
  stixRelationEditionDeleteMutation,
} from '../common/stix_relations/StixRelationEdition';

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

const reportKnowledgeGraphStixEntityQuery = graphql`
  query ReportKnowledgeGraphStixRelationQuery($id: String!) {
    stixEntity(id: $id) {
      id
      name
      description
      entity_type
    }
  }
`;

export const reportKnowledgeGraphtMutationRelationAdd = graphql`
  mutation ReportKnowledgeGraphRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        id
        from {
          ...ReportKnowledgeGraph_report
        }
      }
    }
  }
`;

export const reportKnowledgeGraphtMutationRelationDelete = graphql`
  mutation ReportKnowledgeGraphRelationDeleteMutation(
    $id: ID!
    $toId: String
    $relationType: String
    $relationId: ID
  ) {
    reportEdit(id: $id) {
      relationDelete(
        relationId: $relationId
        toId: $toId
        relationType: $relationType
      ) {
        ...ReportKnowledgeGraph_report
      }
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

const GRAPHER$ = new Subject().pipe(debounce(() => timer(2000)));

class ReportKnowledgeGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openCreateRelation: false,
      createRelationFrom: null,
      createRelationTo: null,
      openEditEntity: false,
      editEntityId: null,
      openEditRelation: false,
      editRelationId: null,
      currentNode: null,
      currentLink: null,
      lastLinkFirstSeen: null,
      lastLinkLastSeen: null,
      lastCreatePosition: { x: 0, y: 0 },
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
    const model = this.props.engine.getDiagramModel();
    const added = differenceWith(
      (x, y) => x.node.id === y.node.id,
      this.props.report.objectRefs.edges,
      prevProps.report.objectRefs.edges,
    );
    const removed = differenceWith(
      (x, y) => x.node.id === y.node.id,
      prevProps.report.objectRefs.edges,
      this.props.report.objectRefs.edges,
    );
    // if a node has been added, add in graph
    if (added.length > 0) {
      const newNodes = map(
        (n) => new EntityNodeModel({
          id: n.node.id,
          name: n.node.name,
          type: n.node.entity_type,
        }),
        added,
      );
      forEach((n) => {
        n.setPosition(
          this.state.lastCreatePosition.x + 100,
          this.state.lastCreatePosition.y + 100,
        );
        this.setState({
          lastCreatePosition: {
            x: this.state.lastCreatePosition.x + 100,
            y: this.state.lastCreatePosition.y + 100,
          },
        });
        n.addListener({ selectionChanged: this.handleSelection.bind(this) });
        model.addNode(n);
      }, newNodes);
      this.props.engine.repaintCanvas();
    }
    // if a node has been removed, remove in graph
    if (removed.length > 0) {
      const removedIds = map((n) => n.node.id, removed);
      forEach((n) => {
        if (removedIds.includes(n.extras.id)) {
          const port = n.getPort('main');
          const { links } = port;
          forEach((link) => {
            let relevantPort = link.sourcePort;
            if (relevantPort.id === port.id) {
              relevantPort = link.targetPort;
            }
            if (
              relevantPort.parent.type === 'relation'
              && values(relevantPort.links).length <= 2
            ) {
              relevantPort.parent.remove();
            }
          }, values(links));
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
        name: n.node.name,
        type: n.node.entity_type,
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

    // add relations
    const createdRelations = [];
    forEach((l) => {
      if (!includes(l.node.id, createdRelations)) {
        const newNode = new RelationNodeModel({
          id: l.node.id,
          type: l.node.relationship_type,
          first_seen: l.node.first_seen,
          last_seen: l.node.last_seen,
        });
        newNode.addListener({
          selectionChanged: this.handleSelection.bind(this),
        });
        const position = pathOr(
          null,
          ['nodes', l.node.id, 'position'],
          graphData,
        );
        if (position && position.x !== undefined && position.y !== undefined) {
          newNode.setPosition(position.x, position.y);
        }
        model.addNode(newNode);
        createdRelations.push(l.node.id);
      }
    }, relations);
    // build usables nodes object
    const finalNodes = model.getNodes();
    const finalNodesObject = pipe(
      values,
      map((n) => ({ id: n.extras.id, node: n })),
      indexBy(prop('id')),
    )(finalNodes);

    // add links
    const createdLinks = [];
    forEach((l) => {
      if (!includes(l.node.id, createdLinks)) {
        const sourceFromPort = finalNodesObject[l.node.from.id]
          ? finalNodesObject[l.node.from.id].node.getPort('main')
          : null;
        const sourceToPort = finalNodesObject[l.node.id]
          ? finalNodesObject[l.node.id].node.getPort('main')
          : null;
        if (sourceFromPort !== null && sourceToPort !== null) {
          const newLinkSource = new GlobalLinkModel();
          newLinkSource.setSourcePort(sourceFromPort);
          newLinkSource.setTargetPort(sourceToPort);
          model.addLink(newLinkSource);
        }
        const targetFromPort = finalNodesObject[l.node.id]
          ? finalNodesObject[l.node.id].node.getPort('main')
          : null;
        const targetToPort = finalNodesObject[l.node.to.id]
          ? finalNodesObject[l.node.to.id].node.getPort('main')
          : null;
        if (targetFromPort !== null && targetToPort !== null) {
          const newLinkTarget = new GlobalLinkModel();
          newLinkTarget.setSourcePort(targetFromPort);
          newLinkTarget.setTargetPort(targetToPort);
          model.addLink(newLinkTarget);
        }
        createdLinks.push(l.node.id);
      }
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

  // eslint-disable-next-line class-methods-use-this
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
        // handle entity deletion
        if (node.type === 'entity') {
          commitMutation({
            mutation: reportKnowledgeGraphtMutationRelationDelete,
            variables: {
              id: this.props.report.id,
              toId: node.extras.id,
              relationType: 'object_refs',
            },
          });
        }
        if (node.type === 'relation') {
          fetchQuery(reportKnowledgeGraphCheckRelationQuery, {
            id: node.extras.id,
          }).then((data) => {
            if (data.stixRelation.reports.edges.length === 1) {
              commitMutation({
                mutation: stixRelationEditionDeleteMutation,
                variables: {
                  id: node.extras.id,
                },
              });
            } else {
              commitMutation({
                mutation: reportKnowledgeGraphtMutationRelationDelete,
                variables: {
                  id: this.props.report.id,
                  toId: node.extras.id,
                  relationType: 'object_refs',
                },
              });
            }
          });
        }
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

  handleSelection(event) {
    if (event.isSelected === true && event.edit === true) {
      if (event.entity instanceof EntityNodeModel) {
        this.setState({
          openEditEntity: true,
          editEntityId: event.entity.extras.id,
          currentNode: event.entity,
        });
      }
      if (event.entity instanceof RelationNodeModel) {
        this.setState({
          openEditRelation: true,
          editRelationId: event.entity.extras.id,
          currentNode: event.entity,
        });
      }
    }
    if (event.isSelected === true && event.remove === true) {
      this.handleRemoveNode(event.entity);
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

  handleLinkCreation(event) {
    const model = this.props.engine.getDiagramModel();
    const currentLinks = model.getLinks();
    const currentLinksPairs = map(
      (n) => ({
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
        (n) => (n.source === linkPair.source && n.target === linkPair.target)
          || (n.source === linkPair.target && n.target === linkPair.source),
        currentLinksPairs,
      );
      if (link.targetPort === null || link.sourcePort === link.targetPort) {
        link.remove();
      } else if (filteredCurrentLinks.length === 1) {
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

  handleResultRelationCreation(result) {
    const model = this.props.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    this.setState({
      lastLinkFirstSeen: result.first_seen,
      lastLinkLastSeen: result.last_seen,
    });
    const input = {
      fromRole: 'knowledge_aggregation',
      toRole: 'so',
      toId: result.id,
      through: 'object_refs',
    };
    commitMutation({
      mutation: reportKnowledgeGraphtMutationRelationAdd,
      variables: {
        id: this.props.report.id,
        input,
      },
      onCompleted: () => {
        const newNode = new RelationNodeModel({
          id: result.id,
          type: result.relationship_type,
          first_seen: result.first_seen,
          last_seen: result.last_seen,
        });
        newNode.addListener({
          selectionChanged: this.handleSelection.bind(this),
        });
        if (
          linkObject.points
          && linkObject.points[0]
          && linkObject.points[0].x
          && linkObject.points[0].y
        ) {
          newNode.setPosition(
            linkObject.points[0].x,
            linkObject.points[0].y + 100,
          );
        }
        model.addNode(newNode);
        this.props.engine.repaintCanvas();

        const newNodeObject = model.getNode(newNode);
        const relationMainPort = newNodeObject.getPort('main');
        const sourceFromPort = linkObject.sourcePort;
        const newLinkSource = new GlobalLinkModel();
        newLinkSource.setSourcePort(sourceFromPort);
        newLinkSource.setTargetPort(relationMainPort);
        model.addLink(newLinkSource);

        const targetToPort = linkObject.targetPort;
        const newLinkTarget = new GlobalLinkModel();
        newLinkTarget.setSourcePort(relationMainPort);
        newLinkTarget.setTargetPort(targetToPort);
        model.addLink(newLinkTarget);
        linkObject.remove();
        this.props.engine.repaintCanvas();
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

  handleCloseEntityEdition() {
    const { editEntityId, currentNode } = this.state;
    this.setState({
      openEditEntity: false,
      editEntityId: null,
      currentNode: null,
    });
    setTimeout(() => {
      fetchQuery(reportKnowledgeGraphStixEntityQuery, {
        id: editEntityId,
      }).then((data) => {
        const { stixEntity } = data;
        const model = this.props.engine.getDiagramModel();
        const nodeObject = model.getNode(currentNode);
        nodeObject.setExtras({
          id: currentNode.extras.id,
          name: stixEntity.name,
          type: stixEntity.entity_type,
        });
        this.props.engine.repaintCanvas();
      });
    }, 1500);
  }

  handleCloseRelationEdition() {
    const { editRelationId, currentNode } = this.state;
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentNode: null,
    });
    setTimeout(() => {
      fetchQuery(reportKnowledgeGraphRelationQuery, {
        id: editRelationId,
      }).then((data) => {
        const { stixRelation } = data;
        const model = this.props.engine.getDiagramModel();
        const nodeObject = model.getNode(currentNode);
        nodeObject.setExtras({
          id: currentNode.extras.id,
          type: stixRelation.relationship_type,
          first_seen: stixRelation.first_seen,
          last_seen: stixRelation.last_seen,
        });
        this.props.engine.repaintCanvas();
      });
    }, 1500);
  }

  handleRemoveNode(node) {
    const model = this.props.engine.getDiagramModel();
    const nodeObject = model.getNode(node);
    const port = nodeObject.getPort('main');
    const { links } = port;
    forEach((link) => {
      let relevantPort = link.sourcePort;
      if (relevantPort.id === port.id) {
        relevantPort = link.targetPort;
      }
      if (
        relevantPort.parent.type === 'relation'
        && values(relevantPort.links).length <= 2
      ) {
        relevantPort.parent.remove();
      }
    }, values(links));
    nodeObject.remove();
    this.props.engine.repaintCanvas();
  }

  autoDistribute(rankdir) {
    const model = this.props.engine.getDiagramModel();
    const nodes = model.getNodes();
    map((node) => {
      node.setSelected(false);
    }, nodes);
    const serialized = model.serializeDiagram();
    const distributedSerializedDiagram = distributeElements(
      serialized,
      rankdir,
    );
    const distributedDeSerializedModel = new DiagramModel();
    distributedDeSerializedModel.deSerializeDiagram(
      distributedSerializedDiagram,
      this.props.engine,
    );
    // add listeners
    distributedDeSerializedModel.addListener({
      nodesUpdated: this.handleNodeChanges.bind(this),
      linksUpdated: this.handleLinksChange.bind(this),
    });
    this.props.engine.setDiagramModel(distributedDeSerializedModel);
    const newNodes = distributedDeSerializedModel.getNodes();
    map((node) => {
      node.addListener({
        selectionChanged: this.handleSelection.bind(this),
      });
    }, newNodes);
    this.props.engine.repaintCanvas();
  }

  distribute(rankdir) {
    this.autoDistribute(rankdir);
    this.props.engine.zoomToFit();
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
      openEditEntity,
      editEntityId,
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
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.distribute.bind(this, 'LR')}
          style={{ left: 140 }}
        >
          <GraphOutline style={{ transform: 'rotate(-90deg)' }} />
        </IconButton>
        <IconButton
          color="primary"
          className={classes.icon}
          onClick={this.distribute.bind(this, 'TB')}
          style={{ left: 190 }}
        >
          <GraphOutline />
        </IconButton>
        <DiagramWidget
          className={classes.canvas}
          deleteKeys={[]}
          diagramEngine={engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleMovesChange.bind(this)}
        />
        <ReportAddObjectRefs
          reportId={report.id}
          reportObjectRefs={report.objectRefs.edges}
          knowledgeGraph={true}
          defaultCreatedByRef={pathOr(null, ['createdByRef', 'node'], report)}
          defaultMarkingDefinition={
            pathOr([], ['markingDefinitions', 'edges'], report).length > 0
              ? pathOr([], ['markingDefinitions', 'edges'], report)[0].node
              : null
          }
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
          defaultCreatedByRef={pathOr(null, ['createdByRef', 'node'], report)}
          defaultMarkingDefinition={
            pathOr([], ['markingDefinitions', 'edges'], report).length > 0
              ? pathOr([], ['markingDefinitions', 'edges'], report)[0].node
              : null
          }
        />
        <StixRelationEdition
          open={openEditRelation}
          stixRelationId={editRelationId}
          handleClose={this.handleCloseRelationEdition.bind(this)}
        />
        <StixDomainEntityEdition
          open={openEditEntity}
          stixDomainEntityId={editEntityId}
          handleClose={this.handleCloseEntityEdition.bind(this)}
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
        name
        graph_data
        published
        source_confidence_level
        createdByRef {
          node {
            id
            name
            entity_type
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
            }
          }
        }
        objectRefs {
          edges {
            node {
              id
              entity_type
              name
              description
              created_at
              updated_at
            }
          }
        }
        relationRefs {
          edges {
            node {
              id
              relationship_type
              first_seen
              last_seen
              fromRole
              from {
                id
                entity_type
                name
              }
              toRole
              to {
                id
                entity_type
                name
              }
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ReportKnowledgeGraph);
