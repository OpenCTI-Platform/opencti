import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, pipe, forEach, append, values,
  pathOr, filter, last, head, pluck, includes,
  indexBy, prop,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  DiagramEngine,
  DiagramModel,
  DiagramWidget,
  MoveItemsAction,
} from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import { debounce } from 'rxjs/operators/index';
import { Subject, timer } from 'rxjs/index';
import { yearFormat } from '../../../utils/Time';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import EntityPortFactory from '../../../components/graph_node/EntityPortFactory';
import EntityLinkFactory from '../../../components/graph_node/EntityLinkFactory';
import EntityLabelFactory from '../../../components/graph_node/EntityLabelFactory';
import EntityLabelModel from '../../../components/graph_node/EntityLabelModel';
import EntityLinkModel from '../../../components/graph_node/EntityLinkModel';
import { stixDomainEntityMutationFieldPatch } from './StixDomainEntityEditionOverview';
import StixDomainEntityAddObjectRefs from './StixDomainEntityAddObjectRefs';
import StixRelationCreation, { stixRelationCreationDeleteMutation } from '../stix_relation/StixRelationCreation';
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
});

const GRAPHER$ = new Subject().pipe(debounce(() => timer(1500)));

class StixDomainEntityKnowledgeGraphComponent extends Component {
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
    this.saving = false;
    this.engine = new DiagramEngine();
    this.engine.installDefaultFactories();
    this.engine.registerPortFactory(new EntityPortFactory());
    this.engine.registerNodeFactory(new EntityNodeFactory());
    this.engine.registerLinkFactory(new EntityLinkFactory());
    this.engine.registerLabelFactory(new EntityLabelFactory());
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
    if (this.props.stixDomainEntity.graph_data !== prevProps.stixDomainEntity.graph_data) {
      this.initialize();
      this.forceUpdate();
    }
    if (this.props.firstSeenYear !== prevProps.firstSeenYear) {
      const model = this.engine.getDiagramModel();
      const links = model.getLinks();
      forEach((l) => {
        if (yearFormat(pathOr('1970-01-01', ['extras', 'relation', 'first_seen'], l)) === this.props.firstSeenYear) {
          l.setColor('#ff3d00');
        } else {
          l.setColor('#00bcd4');
        }
      }, values(links));
      this.forceUpdate();
    }
  }

  initialize() {
    const { stixDomainEntity, stixDomainEntity: { stixRelations } } = this.props;
    // prepare actual nodes & relations
    const actualNodes = append(stixDomainEntity, map(n => n.to, stixRelations.edges));
    const actualRelations = stixRelations.edges;
    const actualNodesIds = pluck('id', actualNodes);
    const actualRelationsIds = pipe(map(n => n.node), pluck('id'))(actualRelations);
    // create a new model, component is mounted!
    const model = new DiagramModel();
    // decode graph data if any
    if (Array.isArray(stixDomainEntity.graph_data) && head(stixDomainEntity.graph_data).length > 0) {
      const graphData = Buffer.from(head(stixDomainEntity.graph_data), 'base64').toString('ascii');
      const decodedGraphData = JSON.parse(graphData);
      model.deSerializeDiagram(decodedGraphData, this.engine);
    }
    // sync nodes & links
    // check deleted nodes
    const nodes = model.getNodes();
    const nodesIds = map(n => pathOr(null, ['extras', 'id'], n), values(nodes));
    forEach((n) => {
      if (includes(pathOr(null, ['extras', 'id'], n), actualNodesIds)) {
        n.setSelected(false);
        n.addListener({ selectionChanged: this.handleSelection.bind(this) });
      } else {
        model.removeNode(n);
      }
    }, values(nodes));
    // check added nodes
    forEach((n) => {
      if (!includes(n.id, nodesIds)) {
        const newNode = new EntityNodeModel({
          id: n.id,
          name: n.name,
          type: n.type,
        });
        newNode.addListener({ selectionChanged: this.handleSelection.bind(this) });
        model.addNode(newNode);
      }
    }, actualNodes);
    const finalNodes = model.getNodes();
    const finalNodesObject = pipe(
      values,
      map(n => ({ id: n.extras.id, node: n })),
      indexBy(prop('id')),
    )(finalNodes);
    const links = model.getLinks();
    const linksIds = map(l => pathOr(null, ['extras', 'relation', 'id'], l), values(links));
    forEach((l) => {
      if (includes(pathOr(null, ['extras', 'relation', 'id'], l), actualRelationsIds)) {
        l.addListener({ selectionChanged: this.handleSelection.bind(this) });
      } else {
        model.removeLink(l);
      }
    }, values(links));
    forEach((l) => {
      if (!includes(l.node.id, linksIds)) {
        const fromPort = finalNodesObject[this.props.stixDomainEntity.id] ? finalNodesObject[this.props.stixDomainEntity.id].node.getPort('main') : null;
        const toPort = finalNodesObject[l.to.id] ? finalNodesObject[l.to.id].node.getPort('main') : null;
        const newLink = new EntityLinkModel();
        newLink.setExtras({
          relation: l.node,
        });
        newLink.setSourcePort(fromPort);
        newLink.setTargetPort(toPort);
        const label = new EntityLabelModel();
        label.setLabel(l.node.relationship_type);
        label.setFirstSeen(l.node.first_seen);
        label.setLastSeen(l.node.last_seen);
        newLink.addLabel(label);
        newLink.addListener({ selectionChanged: this.handleSelection.bind(this) });
        model.addLink(newLink);
      }
    }, actualRelations);
    // set the model
    model.addListener({
      zoomUpdated: this.handleSaveGraph.bind(this),
      linksUpdated: this.handleLinksChange.bind(this),
    });
    this.engine.setDiagramModel(model);
  }

  saveGraph() {
    if (this.saving === false && this.props.isSavable()) {
      this.saving = true;
      const model = this.engine.getDiagramModel();
      const graphData = JSON.stringify(model.serializeDiagram());
      const encodedGraphData = Buffer.from(graphData).toString('base64');
      commitMutation({
        mutation: stixDomainEntityMutationFieldPatch,
        variables: { id: this.props.stixDomainEntity.id, input: { key: 'graph_data', value: encodedGraphData } },
        onCompleted: () => {
          this.saving = false;
        },
      });
    }
  }

  handleSaveGraph() {
    GRAPHER$.next({ action: 'update' });
  }

  handleMovesChange(event) {
    if (event instanceof MoveItemsAction) {
      this.handleSaveGraph();
    }
    return true;
  }

  handleLinksChange(event) {
    this.handleLinkDeletion(event);
    event.link.addListener({
      targetPortChanged: this.handleLinkCreation.bind(this),
    });
    return true;
  }

  handleLinkCreation(event) {
    const model = this.engine.getDiagramModel();
    const currentLinks = model.getLinks();
    const currentLinksPairs = map(n => ({ source: n.sourcePort.id, target: pathOr(null, ['targetPort', 'id'], n) }), values(currentLinks));
    if (event.port !== undefined) {
      // ensure that the links are not circular on the same element
      const link = last(values(event.port.links));
      const linkPair = { source: link.sourcePort.id, target: pathOr(null, ['targetPort', 'id'], link) };
      const filteredCurrentLinks = filter(n => (
        n.source === linkPair.source && n.target === linkPair.target)
        || (n.source === linkPair.target && n.target === linkPair.source),
      currentLinksPairs);
      if (link.targetPort === null || (link.sourcePort === link.targetPort)) {
        model.removeLink(link);
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

  handleLinkDeletion(event) {
    const model = this.engine.getDiagramModel();
    const currentLinks = model.getLinks();
    const currentLinksPairs = map(n => ({ source: n.sourcePort.id, target: pathOr(null, ['targetPort', 'id'], n) }), values(currentLinks));
    if (event.isCreated === false) {
      if (event.link !== undefined) {
        const { link } = event;
        // ensure that the link is not circular on the same element
        if (link.targetPort !== null && (link.sourcePort !== link.targetPort)) {
          const linkPair = { source: link.sourcePort.id, target: pathOr(null, ['targetPort', 'id'], link) };
          const filteredCurrentLinks = filter(n => (
            n.source === linkPair.source && n.target === linkPair.target)
            || (n.source === linkPair.target && n.target === linkPair.source),
          currentLinksPairs);
          if (filteredCurrentLinks.length === 0) {
            if (link.extras && link.extras.relation) {
              commitMutation({
                mutation: stixRelationCreationDeleteMutation,
                variables: {
                  id: link.extras.relation.id,
                },
              });
            }
          }
        }
        this.handleSaveGraph();
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
    const model = this.engine.getDiagramModel();
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
    const model = this.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    const label = new EntityLabelModel();
    label.setLabel(result.relationship_type);
    label.setFirstSeen(result.first_seen);
    label.setLastSeen(result.last_seen);
    linkObject.addLabel(label);
    linkObject.setExtras({
      relation: result,
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
    const model = this.engine.getDiagramModel();
    const linkObject = model.getLink(this.state.currentLink);
    linkObject.remove();
    this.setState({
      openEditRelation: false,
      editRelationId: null,
      currentLink: null,
    });
  }

  render() {
    const { classes, stixDomainEntity } = this.props;
    const {
      openCreateRelation, createRelationFrom, createRelationTo, openEditRelation, editRelationId,
    } = this.state;
    return (
      <div className={classes.container}>
        <DiagramWidget
          className={classes.canvas}
          diagramEngine={this.engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleMovesChange.bind(this)}
        />
        <StixDomainEntityAddObjectRefs
          stixDomainEntityId={stixDomainEntity.id}
          stixDomainEntityObjectRefs={map(n => n.to, stixDomainEntity.stixRelations.edges)}
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
          handleClose={this.handleCloseRelationEdition.bind(this)}
          handleDelete={this.handleDeleteRelation.bind(this)}
        />
      </div>
    );
  }
}

StixDomainEntityKnowledgeGraphComponent.propTypes = {
  stixDomainEntity: PropTypes.object,
  firstSeenYear: PropTypes.string,
  isSavable: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainEntityKnowledgeGraph = createFragmentContainer(StixDomainEntityKnowledgeGraphComponent, {
  stixDomainEntity: graphql`
      fragment StixDomainEntityKnowledgeGraph_stixDomainEntity on StixDomainEntity @argumentDefinitions(
          toTypes: {type: "[String]"},
          firstSeenStart: {type: "DateTime"},
          firstSeenStop: {type: "DateTime"},
          lastSeenStart: {type: "DateTime"},
          lastSeenStop: {type: "DateTime"},
          weights: {type: "[Int]"},
          count: {type: "Int", defaultValue: 50}
      ) {
          id
          type
          name
          graph_data
          stixRelations(toTypes: $toTypes, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, weights: $weights, first: $count)
          {
              edges {
                  node {
                      id
                      relationship_type
                      description
                      first_seen
                      last_seen
                  }
                  to {
                      id
                      type
                      name
                  }
              }
          }
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKnowledgeGraph);
