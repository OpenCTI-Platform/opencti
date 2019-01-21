import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Graph } from 'react-d3-graph';
import { compose, map, append } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import GraphNode from '../../../components/GraphNode';
import ReportAddObjectRefs from './ReportAddObjectRefs';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
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

const graphConfig = {
  nodeHighlightBehavior: true,
  node: {
    renderLabel: false,
    size: 700,
    svg: '',
    symbolType: '',
    viewGenerator: node => <GraphNode node={node}/>,
  },
  link: {
    highlightColor: 'lightblue',
  },
};

class ReportKnowledgeGraphComponent extends Component {
  render() {
    const { classes, report } = this.props;
    const objectNodes = map(n => ({
      id: n.node.id,
      name: n.node.name,
      entity_type: n.node.type,
    }), report.objectRefs.edges);
    const nodes = append({
      id: report.id,
      name: report.name,
      entity_type: 'report',
    }, objectNodes);

    const data = {
      nodes,
      links: [],
    };

    return (
      <div className={classes.container}>
        <ReportAddObjectRefs reportId={report.id} reportObjectRefs={report.objectRefs.edges}/>
        <Graph
          id='ReportGraph'
          data={data}
          config={graphConfig}
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
