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
  propOr,
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
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import Alert from '@material-ui/lab/Alert';
import AlertTitle from '@material-ui/lab/AlertTitle/AlertTitle';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import EntityNodeModel from '../../../../components/graph_node/EntityNodeModel';
import GlobalLinkModel from '../../../../components/graph_node/GlobalLinkModel';
import RelationNodeModel from '../../../../components/graph_node/RelationNodeModel';
import distributeElements from '../../../../utils/DagreHelper';
import { serializeGraph } from '../../../../utils/GraphHelper';
import { dateFormat } from '../../../../utils/Time';
import { reportMutationFieldPatch } from './ReportEditionOverview';
// TODO @SAM Fix cyclic redundancies
// eslint-disable-next-line import/no-cycle
import ContainerAddStixCoreObjects from '../../common/containers/ContainerAddStixCoreObjects';
import StixCoreRelationshipCreation from '../../common/stix_core_relationships/StixCoreRelationshipCreation';
import StixDomainObjectEdition from '../../common/stix_domain_objects/StixDomainObjectEdition';
import StixCoreRelationshipEdition, {
  stixCoreRelationshipEditionDeleteMutation,
} from '../../common/stix_core_relationships/StixCoreRelationshipEdition';

const ignoredTypes = ['Note', 'Opinion', 'Report'];

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

const reportKnowledgeGraphStixCoreObjectQuery = graphql`
  query ReportKnowledgeGraphStixCoreObjectQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
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

const reportKnowledgeGraphStixCoreRelationshipQuery = graphql`
  query ReportKnowledgeGraphStixCoreRelationshipQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      id
      start_time
      stop_time
      confidence
      relationship_type
    }
  }
`;

export const reportKnowledgeGraphtMutationRelationAddMutation = graphql`
  mutation ReportKnowledgeGraphRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
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

export const reportKnowledgeGraphtMutationRelationDeleteMutation = graphql`
  mutation ReportKnowledgeGraphRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    reportEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ReportKnowledgeGraph_report
      }
    }
  }
`;

const reportKnowledgeGraphCheckRelationQuery = graphql`
  query ReportKnowledgeGraphCheckRelationQuery($id: String!) {
    stixCoreRelationship(id: $id) {
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
    const propsNodes = filter(
      (n) => !n.node.relationship_type
        && !includes(n.node.entity_type, ignoredTypes),
      this.props.report.objects.edges,
    );
    const prevPropsNodes = filter(
      (n) => !n.node.relationship_type
        && !includes(n.node.entity_type, ignoredTypes),
      prevProps.report.objects.edges,
    );
    const added = differenceWith(
      (x, y) => x.node.id === y.node.id,
      propsNodes,
      prevPropsNodes,
    );
    const removed = differenceWith(
      (x, y) => x.node.id === y.node.id,
      prevPropsNodes,
      prevPropsNodes,
    );
    // if a node has been added, add in graph
    if (added.length > 0) {
      const newNodes = map(
        (n) => new EntityNodeModel({
          id: n.node.id,
          name:
              n.node.name
              || n.node.observable_value
              || n.node.attribute_abstract
              || n.node.opinion,
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

    if (
      this.props.report.x_opencti_graph_data
      !== prevProps.report.x_opencti_graph_data
    ) {
      this.updateView();
    }
  }

  initialize() {
    const model = new DiagramModel();
    // prepare nodes & relations
    const nodes = filter(
      (n) => !n.node.relationship_type
        && !includes(n.node.entity_type, ignoredTypes),
      this.props.report.objects.edges,
    );
    const relations = filter(
      (n) => n.node.relationship_type,
      this.props.report.objects.edges,
    );

    // decode graph data if any
    let graphData = {};
    if (
      this.props.report.x_opencti_graph_data
      && this.props.report.x_opencti_graph_data.length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(this.props.report.x_opencti_graph_data, 'base64').toString(
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
        name:
          n.node.name
          || n.node.observable_value
          || n.node.attribute_abstract
          || n.node.opinion,
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
          start_time: l.node.start_time,
          stop_time: l.node.stop_time,
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
      this.props.report.x_opencti_graph_data
      && this.props.report.x_opencti_graph_data.length > 0
    ) {
      graphData = JSON.parse(
        Buffer.from(this.props.report.x_opencti_graph_data, 'base64').toString(
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
      mutation: reportMutationFieldPatch,
      variables: {
        id: this.props.report.id,
        input: { key: 'x_opencti_graph_data', value: graphData },
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
            mutation: reportKnowledgeGraphtMutationRelationDeleteMutation,
            variables: {
              id: this.props.report.id,
              toId: node.extras.id,
              relationship_type: 'object',
            },
          });
        }
        if (node.type === 'relation') {
          fetchQuery(reportKnowledgeGraphCheckRelationQuery, {
            id: node.extras.id,
          }).then((data) => {
            if (data.stixCoreRelationship.reports.edges.length === 1) {
              commitMutation({
                mutation: stixCoreRelationshipEditionDeleteMutation,
                variables: {
                  id: node.extras.id,
                },
              });
            } else {
              commitMutation({
                mutation: reportKnowledgeGraphtMutationRelationDeleteMutation,
                variables: {
                  id: this.props.report.id,
                  toId: node.extras.id,
                  relationship_type: 'object',
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
      lastLinkFirstSeen: result.start_time,
      lastLinkLastSeen: result.stop_time,
    });
    const input = {
      toId: result.id,
      relationship_type: 'object',
    };
    commitMutation({
      mutation: reportKnowledgeGraphtMutationRelationAddMutation,
      variables: {
        id: this.props.report.id,
        input,
      },
      onCompleted: () => {
        const newNode = new RelationNodeModel({
          id: result.id,
          type: result.relationship_type,
          start_time: result.start_time,
          stop_time: result.stop_time,
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
      fetchQuery(reportKnowledgeGraphStixCoreObjectQuery, {
        id: editEntityId,
      }).then((data) => {
        const { stixCoreObject } = data;
        const model = this.props.engine.getDiagramModel();
        const nodeObject = model.getNode(currentNode);
        nodeObject.setExtras({
          id: currentNode.extras.id,
          name:
            stixCoreObject.name
            || stixCoreObject.observable_value
            || stixCoreObject.attribute_abstract
            || stixCoreObject.opinion,
          type: stixCoreObject.entity_type,
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
      fetchQuery(reportKnowledgeGraphStixCoreRelationshipQuery, {
        id: editRelationId,
      }).then((data) => {
        const { stixCoreRelationship } = data;
        const model = this.props.engine.getDiagramModel();
        const nodeObject = model.getNode(currentNode);
        nodeObject.setExtras({
          id: currentNode.extras.id,
          type: stixCoreRelationship.relationship_type,
          start_time: stixCoreRelationship.start_time,
          stop_time: stixCoreRelationship.stop_time,
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
    const {
      classes, engine, report, t,
    } = this.props;
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
      <div>
        {report.objects.edges.length > 200 ? (
          <div className={classes.container} ref={this.diagramContainer}>
            <Alert severity="info" style={{ marginTop: 20 }}>
              <AlertTitle>{t('Too many objects')}</AlertTitle>
              {t(
                'This report contains too many objects to be displayed as a graph. We are working on a new visualization which will allow large graph to be displayed in the future.',
              )}
            </Alert>
          </div>
        ) : (
          <div className={classes.container} ref={this.diagramContainer}>
            <IconButton
              color="primary"
              className={classes.icon}
              onClick={this.zoomToFit.bind(this)}
              style={{ left: 200 }}
            >
              <AspectRatio />
            </IconButton>
            <IconButton
              color="primary"
              className={classes.icon}
              onClick={this.distribute.bind(this, 'LR')}
              style={{ left: 250 }}
            >
              <GraphOutline style={{ transform: 'rotate(-90deg)' }} />
            </IconButton>
            <IconButton
              color="primary"
              className={classes.icon}
              onClick={this.distribute.bind(this, 'TB')}
              style={{ left: 300 }}
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
            <ContainerAddStixCoreObjects
              containerId={report.id}
              containerStixCoreObjects={report.objects.edges}
              knowledgeGraph={true}
              defaultCreatedBy={propOr(null, 'createdBy', report)}
              defaultMarkingDefinitions={map(
                (n) => n.node,
                pathOr([], ['objectMarking', 'edges'], report),
              )}
            />
            <StixCoreRelationshipCreation
              open={openCreateRelation}
              from={createRelationFrom}
              to={createRelationTo}
              firstSeen={lastLinkFirstSeen || dateFormat(report.published)}
              lastSeen={lastLinkLastSeen || dateFormat(report.published)}
              weight={report.confidence}
              handleClose={this.handleCloseRelationCreation.bind(this)}
              handleResult={this.handleResultRelationCreation.bind(this)}
              defaultCreatedBy={propOr(null, 'createdBy', report)}
              defaultMarkingDefinitions={map(
                (n) => n.node,
                pathOr([], ['objectMarking', 'edges'], report),
              )}
            />
            <StixCoreRelationshipEdition
              open={openEditRelation}
              stixCoreRelationshipId={editRelationId}
              handleClose={this.handleCloseRelationEdition.bind(this)}
            />
            <StixDomainObjectEdition
              open={openEditEntity}
              stixDomainObjectId={editEntityId}
              handleClose={this.handleCloseEntityEdition.bind(this)}
            />
          </div>
        )}
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
        x_opencti_graph_data
        published
        confidence
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
        objects {
          edges {
            node {
              ... on BasicObject {
                id
                entity_type
              }
              ... on StixObject {
                created_at
                updated_at
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
                  ... on AttackPattern {
                    name
                  }
                  ... on Campaign {
                    name
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
                  ... on Indicator {
                    name
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
                  }
                  ... on ThreatActor {
                    name
                  }
                  ... on Tool {
                    name
                  }
                  ... on Vulnerability {
                    name
                  }
                  ... on XOpenCTIIncident {
                    name
                  }
                  ... on StixCyberObservable {
                    observable_value
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
                  ... on AttackPattern {
                    name
                  }
                  ... on Campaign {
                    name
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
                  ... on Indicator {
                    name
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
                  }
                  ... on ThreatActor {
                    name
                  }
                  ... on Tool {
                    name
                  }
                  ... on Vulnerability {
                    name
                  }
                  ... on XOpenCTIIncident {
                    name
                  }
                  ... on StixCyberObservable {
                    observable_value
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

export default compose(inject18n, withStyles(styles))(ReportKnowledgeGraph);
