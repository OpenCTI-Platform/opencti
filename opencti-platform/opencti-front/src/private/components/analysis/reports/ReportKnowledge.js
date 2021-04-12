import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { Route, withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ReportKnowledgeGraph, {
  reportKnowledgeGraphQuery,
} from './ReportKnowledgeGraph';
import Loader from '../../../../components/Loader';
import ReportPopover from './ReportPopover';
import AttackPatternsMatrix from '../../arsenal/attack_patterns/AttackPatternsMatrix';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

export const reportKnowledgeAttackPatternsGraphQuery = graphql`
  query ReportKnowledgeAttackPatternsGraphQuery($id: String) {
    report(id: $id) {
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
      objects(all: true, types: ["Attack-Pattern"]) {
        edges {
          node {
            ... on AttackPattern {
              id
              entity_type
              parent_types
              name
              description
              x_mitre_platforms
              x_mitre_permissions_required
              x_mitre_id
              x_mitre_detection
              isSubAttackPattern
              parentAttackPatterns {
                edges {
                  node {
                    id
                    name
                    description
                    x_mitre_id
                  }
                }
              }
              subAttackPatterns {
                edges {
                  node {
                    id
                    name
                    description
                    x_mitre_id
                  }
                }
              }
              creator {
                id
                name
              }
              killChainPhases {
                edges {
                  node {
                    id
                    kill_chain_name
                    phase_name
                    x_opencti_order
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

class ReportKnowledgeComponent extends Component {
  render() {
    const {
      classes,
      report,
      match: {
        params: { mode },
      },
    } = this.props;
    return (
      <div className={classes.container}>
        <ContainerHeader
          container={report}
          PopoverComponent={<ReportPopover />}
          link={`/dashboard/analysis/reports/${report.id}/knowledge`}
          modes={[
            { key: 'graph', label: 'Graph', current: mode === 'graph' },
            {
              key: 'matrix',
              label: 'Techniques matrix',
              current: mode === 'matrix',
            },
          ]}
        />
        <Route
          exact
          path="/dashboard/analysis/reports/:reportId/knowledge/graph"
          render={() => (
            <QueryRenderer
              query={reportKnowledgeGraphQuery}
              variables={{ id: report.id }}
              render={({ props }) => {
                if (props && props.report) {
                  return <ReportKnowledgeGraph report={props.report} />;
                }
                return <Loader />;
              }}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/analysis/reports/:reportId/knowledge/matrix"
          render={() => (
            <QueryRenderer
              query={reportKnowledgeAttackPatternsGraphQuery}
              variables={{ id: report.id }}
              render={({ props }) => {
                if (props && props.report) {
                  const attackPatterns = R.pipe(
                    R.map((n) => n.node),
                    R.filter((n) => n.entity_type === 'Attack-Pattern'),
                  )(props.report.objects.edges);
                  return (
                    <AttackPatternsMatrix
                      entity={report}
                      attackPatterns={attackPatterns}
                      searchTerm=""
                    />
                  );
                }
                return <Loader />;
              }}
            />
          )}
        />
      </div>
    );
  }
}

ReportKnowledgeComponent.propTypes = {
  report: PropTypes.object,
  mode: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const ReportKnowledge = createFragmentContainer(ReportKnowledgeComponent, {
  report: graphql`
    fragment ReportKnowledge_report on Report {
      id
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ReportKnowledge);
