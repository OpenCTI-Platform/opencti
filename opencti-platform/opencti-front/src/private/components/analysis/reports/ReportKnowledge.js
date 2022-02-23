import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { Route, withRouter } from 'react-router-dom';
import { propOr } from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ReportKnowledgeGraph, {
  reportKnowledgeGraphQuery,
} from './ReportKnowledgeGraph';
import ReportKnowledgeCorrelation, {
  reportKnowledgeCorrelationQuery,
} from './ReportKnowledgeCorrelation';
import Loader from '../../../../components/Loader';
import ReportPopover from './ReportPopover';
import AttackPatternsMatrix from '../../arsenal/attack_patterns/AttackPatternsMatrix';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';

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
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-report-knowledge-${props.report.id}`,
    );
    this.state = {
      currentModeOnlyActive: propOr(false, 'currentModeOnlyActive', params),
      currentColorsReversed: propOr(false, 'currentColorsReversed', params),
      currentKillChain: propOr('mitre-attack', 'currentKillChain', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-report-knowledge-${this.props.report.id}`,
      this.state,
    );
  }

  handleToggleModeOnlyActive() {
    this.setState(
      { currentModeOnlyActive: !this.state.currentModeOnlyActive },
      () => this.saveView(),
    );
  }

  handleToggleColorsReversed() {
    this.setState(
      { currentColorsReversed: !this.state.currentColorsReversed },
      () => this.saveView(),
    );
  }

  handleChangeKillChain(event) {
    const { value } = event.target;
    this.setState({ currentKillChain: value }, () => this.saveView());
  }

  render() {
    const {
      classes,
      report,
      location,
      match: {
        params: { mode },
      },
    } = this.props;
    const { currentModeOnlyActive, currentColorsReversed, currentKillChain } = this.state;
    return (
      <div
        className={classes.container}
        id={location.pathname.includes('matrix') ? 'parent' : 'container'}
      >
        {mode !== 'graph' && (
          <ContainerHeader
            container={report}
            PopoverComponent={<ReportPopover />}
            link={`/dashboard/analysis/reports/${report.id}/knowledge`}
            modes={['graph', 'correlation', 'matrix']}
            currentMode={mode}
            knowledge={true}
          />
        )}
        <Route
          exact
          path="/dashboard/analysis/reports/:reportId/knowledge/graph"
          render={() => (
            <QueryRenderer
              query={reportKnowledgeGraphQuery}
              variables={{ id: report.id }}
              render={({ props }) => {
                if (props && props.report) {
                  return (
                    <ReportKnowledgeGraph report={props.report} mode={mode} />
                  );
                }
                return <Loader />;
              }}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/analysis/reports/:reportId/knowledge/correlation"
          render={() => (
            <QueryRenderer
              query={reportKnowledgeCorrelationQuery}
              variables={{ id: report.id }}
              render={({ props }) => {
                if (props && props.report) {
                  return <ReportKnowledgeCorrelation report={props.report} />;
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
                      currentKillChain={currentKillChain}
                      currentModeOnlyActive={currentModeOnlyActive}
                      currentColorsReversed={currentColorsReversed}
                      handleChangeKillChain={this.handleChangeKillChain.bind(
                        this,
                      )}
                      handleToggleColorsReversed={this.handleToggleColorsReversed.bind(
                        this,
                      )}
                      handleToggleModeOnlyActive={this.handleToggleModeOnlyActive.bind(
                        this,
                      )}
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
