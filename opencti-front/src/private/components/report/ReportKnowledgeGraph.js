import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, forEach, difference, values, pathOr,
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
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import EntityPortFactory from '../../../components/graph_node/EntityPortFactory';
import { reportMutationFieldPatch } from './ReportEditionOverview';
import ReportAddObjectRefs from './ReportAddObjectRefs';
import { reportMutationRelationDelete } from './ReportAddObjectRefsLines';

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
    minHeight: '100vh',
    margin: 0,
    padding: 0,
  },
});

export const reportKnowledgeGraphQuery = graphql`
    query ReportKnowledgeGraphQuery($id: String!) {
        report(id: $id) {
            ...ReportKnowledgeGraph_report
        }
    }
`;

const GRAPHER$ = new Subject().pipe(debounce(() => timer(2000)));

class ReportKnowledgeGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.saving = false;
    this.engine = new DiagramEngine();
    this.engine.installDefaultFactories();
    this.engine.registerPortFactory(new EntityPortFactory());
    this.engine.registerNodeFactory(new EntityNodeFactory());
  }

  componentDidMount() {
    // create a new model, component is mounted!
    const model = new DiagramModel();
    model.addListener({
      nodesUpdated: this.handleGraphChange.bind(this),
      linksUpdated: this.handleGraphChange.bind(this),
    });
    // decode graph data if any
    if (this.props.report.graph_data.length > 0) {
      const graphData = Buffer.from(this.props.report.graph_data, 'base64').toString('ascii');
      const decodedGraphData = JSON.parse(graphData);
      model.deSerializeDiagram(decodedGraphData, this.engine);
    }
    // unselect all nodes
    forEach((n) => { n.setSelected(false); }, values(model.getNodes()));
    // set the model
    this.engine.setDiagramModel(model);
    // subscribe to grapher
    GRAPHER$.subscribe({
      next: (message) => {
        if (message.action === 'update') {
          this.saveGraph();
        }
      },
    });
  }

  componentDidUpdate(prevProps) {
    // component has been updated, check changes
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
      const model = this.engine.getDiagramModel();
      const newNodes = map(n => new EntityNodeModel({
        id: n.node.id,
        relationId: n.relation.id,
        name: n.node.name,
        type: n.node.type,
      }), added);
      forEach((n) => {
        model.addNode(n);
      }, newNodes);
      this.forceUpdate();
    }
    // if a node has been removed, remove in graph
    if (removed.length > 0) {
      const model = this.engine.getDiagramModel();
      const removedIds = map(n => n.node.id, removed);
      forEach((n) => {
        if (removedIds.includes(n.extras.id)) {
          model.removeNode(n);
        }
      }, values(model.getNodes()));
      this.forceUpdate();
    }
  }

  saveGraph() {
    if (this.saving === false) {
      this.saving = true;
      const model = this.engine.getDiagramModel();
      const graphData = JSON.stringify(model.serializeDiagram());
      const encodedGraphData = Buffer.from(graphData).toString('base64');
      commitMutation({
        mutation: reportMutationFieldPatch,
        variables: { id: this.props.report.id, input: { key: 'graph_data', value: encodedGraphData } },
        onCompleted: () => {
          this.saving = false;
        },
      });
    }
  }

  handleSaveGraph() {
    GRAPHER$.next({ action: 'update' });
  }

  handleGraphChange(event) {
    console.log(event);
    // if moveaction (drop), save graph for positions
    if (event instanceof MoveItemsAction) {
      this.handleSaveGraph();
    }
    // if deletion of object
    if (event instanceof Object && event.entity !== undefined) {
      if (event.isCreated === false) {
        const nodeRelationId = pathOr(null, ['node', 'extras', 'relationId'], event);
        if (nodeRelationId !== null) {
          commitMutation({
            mutation: reportMutationRelationDelete,
            variables: {
              id: this.props.report.id,
              relationId: nodeRelationId,
            },
          });
        }
      }
      console.log(event);
      this.handleSaveGraph();
    }
    return true;
  }

  render() {
    const { classes, report } = this.props;
    return (
      <div className={classes.container}>
        <ReportAddObjectRefs reportId={report.id} reportObjectRefs={report.objectRefs.edges}/>
        <DiagramWidget
          className={classes.canvas}
          diagramEngine={this.engine}
          inverseZoom={true}
          allowLooseLinks={false}
          maxNumberPointsPerLink={0}
          actionStoppedFiring={this.handleGraphChange.bind(this)}
        />
      </div>
    );
  }
}

ReportKnowledgeGraphComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ReportKnowledgeGraph = createFragmentContainer(ReportKnowledgeGraphComponent, {
  report: graphql`
      fragment ReportKnowledgeGraph_report on Report {
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
)(ReportKnowledgeGraph);
