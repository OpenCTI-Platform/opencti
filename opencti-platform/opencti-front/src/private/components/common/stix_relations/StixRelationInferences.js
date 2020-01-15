import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  forEach,
  compose,
  includes,
  values,
  pipe,
  prop,
  map,
  indexBy,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { DiagramModel, DiagramWidget } from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityNodeModel from '../../../../components/graph_node/EntityNodeModel';
import SimpleLinkModel from '../../../../components/graph_node/SimpleLinkModel';
import SimpleLabelModel from '../../../../components/graph_node/SimpleLabelModel';
import { resolveLink } from '../../../../utils/Entity';

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

class StixRelationInferences extends Component {
  constructor(props) {
    super(props);
    this.container = React.createRef();
  }

  componentDidMount() {
    this.initialize();
  }

  initialize() {
    const { stixRelation, from, to } = this.props;
    const model = new DiagramModel();
    const containerWidth = this.container.current.offsetWidth;

    // add nodes
    const createdNodesIds = [];
    forEach((n) => {
      const inference = n.node;
      if (!includes(inference.from.id, createdNodesIds)) {
        const newNodeFrom = new EntityNodeModel({
          id: inference.from.id,
          name: includes('Stix-Observable', inference.from.parent_types)
            ? inference.from.observable_value
            : inference.from.name,
          type: inference.from.entity_type,
          disabled: true,
        });
        if (inference.from.id === from.id) {
          newNodeFrom.setPosition(30, 20);
        } else if (inference.from.id === to.id) {
          newNodeFrom.setPosition(containerWidth - 170, 280);
        } else {
          newNodeFrom.setPosition(containerWidth / 2 - 120, 140);
        }
        model.addNode(newNodeFrom);
        createdNodesIds.push(inference.from.id);
      }
      if (!includes(inference.to.id, createdNodesIds)) {
        const newNodeTo = new EntityNodeModel({
          id: inference.to.id,
          name: includes('Stix-Observable', inference.to.parent_types)
            ? inference.to.observable_value
            : inference.to.name,
          type: inference.to.entity_type,
          disabled: true,
        });
        if (inference.to.id === from.id) {
          newNodeTo.setPosition(30, 0);
        } else if (inference.to.id === to.id) {
          newNodeTo.setPosition(containerWidth - 170, 280);
        } else {
          newNodeTo.setPosition(containerWidth / 2 - 120, 140);
        }
        model.addNode(newNodeTo);
        createdNodesIds.push(inference.to.id);
      }
    }, stixRelation.inferences.edges);

    const finalNodes = model.getNodes();
    const finalNodesObject = pipe(
      values,
      map((n) => ({ id: n.extras.id, node: n })),
      indexBy(prop('id')),
    )(finalNodes);

    const createdRelationsIds = [];
    forEach((l) => {
      const inference = l.node;
      if (!includes(inference.id, createdRelationsIds)) {
        const fromPort = finalNodesObject[inference.from.id]
          ? finalNodesObject[inference.from.id].node.getPort('main')
          : null;
        const toPort = finalNodesObject[inference.to.id]
          ? finalNodesObject[inference.to.id].node.getPort('main')
          : null;
        const newLink = new SimpleLinkModel();
        newLink.setExtras({
          relation: inference,
          link: `${resolveLink(
            inference.from.entity_type !== 'stix_relation'
              ? inference.from.entity_type
              : inference.to.entity_type,
          )}/${
            inference.from.entity_type !== 'stix_relation'
              ? inference.from.id
              : inference.to.id
          }/knowledge/relations/${inference.id}`,
        });
        newLink.setSourcePort(fromPort);
        newLink.setTargetPort(toPort);
        const label = new SimpleLabelModel();
        label.setExtras([
          {
            id: l.node.id,
            relationship_type: inference.relationship_type,
            inferred: inference.inferred,
          },
        ]);
        newLink.addLabel(label);
        newLink.setInferred(inference.inferred);
        newLink.addListener({
          selectionChanged: this.handleSelection.bind(this),
        });
        model.addLink(newLink);
        createdRelationsIds.push(inference.id);
      }
    }, stixRelation.inferences.edges);

    model.setLocked(true);
    this.props.engine.setDiagramModel(model);
    this.props.engine.repaintCanvas();
  }

  handleSelection(event) {
    if (event.isSelected === true && event.openEdit === true) {
      if (event.entity instanceof SimpleLinkModel) {
        this.props.history.push(event.entity.extras.link);
      }
    }
    return true;
  }

  render() {
    const { classes } = this.props;
    return (
      <div style={{ width: '100%' }} ref={this.container}>
        <DiagramWidget
          deleteKeys={[]}
          className={classes.canvas}
          diagramEngine={this.props.engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
        />
      </div>
    );
  }
}

StixRelationInferences.propTypes = {
  stixRelation: PropTypes.object,
  from: PropTypes.object,
  to: PropTypes.object,
  engine: PropTypes.object,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixRelationInferences);
