import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { Route, withRouter } from 'react-router-dom';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
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
import AttackPatternsMatrix from '../../techniques/attack_patterns/AttackPatternsMatrix';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import ReportKnowledgeTimeLine, {
  reportKnowledgeTimeLineQuery,
} from './ReportKnowledgeTimeLine';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import Filters from '../../common/lists/Filters';
import SearchInput from '../../../../components/SearchInput';
import FilterIconButton from '../../../../components/FilterIconButton';

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
            definition_type
            definition
            x_opencti_order
            x_opencti_color
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
      timeLineDisplayRelationships: propOr(
        false,
        'timeLineDisplayRelationships',
        params,
      ),
      timeLineFunctionalDate: propOr(false, 'timeLineFunctionalDate', params),
      timeLineFilters: propOr({}, 'timeLineFilters', params),
      timeLineSearchTerm: R.propOr('', 'timeLineSearchTerm', params),
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

  handleToggleTimeLineDisplayRelationships() {
    this.setState(
      {
        timeLineDisplayRelationships: !this.state.timeLineDisplayRelationships,
      },
      () => this.saveView(),
    );
  }

  handleToggleTimeLineFunctionalDate() {
    this.setState(
      {
        timeLineFunctionalDate: !this.state.timeLineFunctionalDate,
      },
      () => this.saveView(),
    );
  }

  handleAddTimeLineFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (
      this.state.timeLineFilters[key]
      && this.state.timeLineFilters[key].length > 0
    ) {
      this.setState(
        {
          timeLineFilters: {
            ...this.state.timeLineFilters,
            [key]: isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.timeLineFilters[key],
              ]),
          },
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          timeLineFilters: {
            ...this.state.timeLineFilters,
            [key]: [{ id, value }],
          },
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveTimeLineFilter(key) {
    this.setState(
      { timeLineFilters: R.dissoc(key, this.state.timeLineFilters) },
      () => this.saveView(),
    );
  }

  handleTimeLineSearch(value) {
    this.setState({ timeLineSearchTerm: value }, () => this.saveView());
  }

  render() {
    const {
      classes,
      report,
      t,
      location,
      match: {
        params: { mode },
      },
    } = this.props;
    const {
      currentModeOnlyActive,
      currentColorsReversed,
      currentKillChain,
      timeLineFilters,
      timeLineDisplayRelationships,
      timeLineFunctionalDate,
      timeLineSearchTerm,
    } = this.state;
    let finalFilters = convertFilters(timeLineFilters);
    const defaultTypes = timeLineDisplayRelationships
      ? ['stix-core-relationship']
      : ['Stix-Core-Object'];
    const types = R.head(finalFilters.filter((n) => n.key === 'entity_type'))?.values
      || defaultTypes;
    finalFilters = finalFilters.filter((n) => !['entity_type'].includes(n.key));
    let orderBy = 'created_at';
    if (timeLineFunctionalDate && timeLineDisplayRelationships) {
      orderBy = 'start_time';
    } else if (timeLineFunctionalDate) {
      orderBy = 'created';
    }
    const timeLinePaginationOptions = {
      types,
      search: timeLineSearchTerm,
      filters: finalFilters,
      orderBy,
      orderMode: 'desc',
    };
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
            modes={['graph', 'timeline', 'correlation', 'matrix']}
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
          path="/dashboard/analysis/reports/:reportId/knowledge/timeline"
          render={() => (
            <>
              <div style={{ float: 'left' }}>
                <SearchInput
                  variant="small"
                  onSubmit={this.handleTimeLineSearch.bind(this)}
                  keyword={timeLineSearchTerm}
                />
                <FormControlLabel
                  style={{ marginLeft: 10 }}
                  control={
                    <Switch
                      onChange={this.handleToggleTimeLineDisplayRelationships.bind(
                        this,
                      )}
                      checked={timeLineDisplayRelationships}
                    />
                  }
                  label={t('Display relationships')}
                />
                <FormControlLabel
                  control={
                    <Switch
                      onChange={this.handleToggleTimeLineFunctionalDate.bind(
                        this,
                      )}
                      checked={timeLineFunctionalDate}
                    />
                  }
                  label={t('Use functional dates')}
                />
              </div>
              <Filters
                availableFilterKeys={[
                  'entity_type',
                  'markedBy',
                  'labelledBy',
                  'createdBy',
                  'relationship_type',
                ]}
                availableEntityTypes={[
                  'Stix-Domain-Object',
                  'Stix-Cyber-Observable',
                ]}
                handleAddFilter={this.handleAddTimeLineFilter.bind(this)}
                noDirectFilters={true}
              />
              <FilterIconButton
                filters={timeLineFilters}
                handleRemoveFilter={this.handleRemoveTimeLineFilter}
              />
              <div className="clearfix" />
              <QueryRenderer
                query={reportKnowledgeTimeLineQuery}
                variables={{ id: report.id, ...timeLinePaginationOptions }}
                render={({ props }) => {
                  if (props && props.report) {
                    return (
                      <ReportKnowledgeTimeLine
                        report={props.report}
                        dateAttribute={orderBy}
                        displayRelationships={timeLineDisplayRelationships}
                      />
                    );
                  }
                  return <Loader />;
                }}
              />
            </>
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
