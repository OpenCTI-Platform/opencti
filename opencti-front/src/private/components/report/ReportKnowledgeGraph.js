import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
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

class ReportKnowledgeGraphComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <div className={classes.container}>
        <ReportAddObjectRefs reportId={report.id} reportObjectRefs={report.objectRefs.edges}/>
        {report.objectRefs.edges.map(objectRef => (
            <div key={objectRef.node.id}>{objectRef.node.name}</div>
        ))}
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
