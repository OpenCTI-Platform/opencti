import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, append } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  DiagramEngine,
  DiagramModel,
  DefaultNodeModel,
  LinkModel,
  DefaultPortModel,
  DiagramWidget,
} from 'storm-react-diagrams';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityNodeModel from '../../../components/graph_node/EntityNodeModel';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import SimplePortFactory from '../../../components/graph_node/SimplePortFactory';
import EntityPortModel from '../../../components/graph_node/EntityPortModel';
import ReportAddObjectRefs from './ReportAddObjectRefs';

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

class ReportKnowledgeGraphComponent extends Component {
  constructor(props) {
    super(props);
    this.engine = new DiagramEngine();
    this.engine.installDefaultFactories();
    this.engine.registerPortFactory(new SimplePortFactory('entity', new EntityPortModel()));
    this.engine.registerNodeFactory(new EntityNodeFactory());
  }

  render() {
    const { classes, report } = this.props;

    const nodes = map(n => new EntityNodeModel({
      id: n.node.id,
      name: n.node.name,
      type: n.node.type,
    }), report.objectRefs.edges);

    const model = new DiagramModel();
    console.log(nodes);
    model.addAll(nodes);
    console.log(model);
    this.engine.setDiagramModel(model);

    return (
      <div className={classes.container}>
        <ReportAddObjectRefs reportId={report.id} reportObjectRefs={report.objectRefs.edges}/>
        <DiagramWidget className={classes.canvas} diagramEngine={this.engine} />
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
