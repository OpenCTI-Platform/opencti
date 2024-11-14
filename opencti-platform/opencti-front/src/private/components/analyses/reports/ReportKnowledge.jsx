import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, createRefetchContainer, graphql, useFragment } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import { containerAddStixCoreObjectsLinesRelationAddMutation } from '../../common/containers/ContainerAddStixCoreObjectsLines';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ReportKnowledgeGraph, { reportKnowledgeGraphQuery } from './ReportKnowledgeGraph';
import ReportKnowledgeCorrelation, { reportKnowledgeCorrelationQuery } from './ReportKnowledgeCorrelation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ReportPopover from './ReportPopover';
import AttackPatternsMatrix from '../../techniques/attack_patterns/AttackPatternsMatrix';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import ReportKnowledgeTimeLine, { reportKnowledgeTimeLineQuery } from './ReportKnowledgeTimeLine';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, filtersAfterSwitchLocalMode } from '../../../../utils/filters/filtersUtils';
import ContentKnowledgeTimeLineBar from '../../common/containers/ContainertKnowledgeTimeLineBar';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import withRouter from '../../../../utils/compat_router/withRouter';

export const reportKnowledgeAttackPatternsGraphQuery = graphql`
    query ReportKnowledgeAttackPatternsGraphQuery($id: String!) {
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            ...ReportKnowledgeAttackPatterns_fragment
        }
    }
`;

const ReportAttackPatternsFragment = graphql`
    fragment ReportKnowledgeAttackPatterns_fragment on Report {
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
`;

const AttackPatternMatrixComponent = (props) => {
  const {
    data,
    report,
    currentKillChain,
    currentModeOnlyActive,
    currentColorsReversed,
    handleChangeKillChain,
    handleToggleColorsReversed,
    handleToggleModeOnlyActive,
  } = props;
  const attackPatternObjects = useFragment(ReportAttackPatternsFragment, data.report);
  const attackPatterns = (attackPatternObjects.objects.edges)
    .map((n) => n.node)
    .filter((n) => n.entity_type === 'Attack-Pattern');

  const handleAddEntity = (entity) => {
    const input = {
      toId: entity.id,
      relationship_type: 'object',
    };
    commitMutation({
      mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
      variables: {
        id: report.id,
        input,
      },
      onCompleted: () => {
        props.relay.refetch({ id: report.id });
      },
    });
  };

  return (
    <AttackPatternsMatrix
      entity={report}
      attackPatterns={attackPatterns}
      currentKillChain={currentKillChain}
      currentModeOnlyActive={currentModeOnlyActive}
      currentColorsReversed={currentColorsReversed}
      handleChangeKillChain={handleChangeKillChain}
      handleToggleColorsReversed={handleToggleColorsReversed}
      handleToggleModeOnlyActive={handleToggleModeOnlyActive}
      handleAdd={handleAddEntity}
    />
  );
};

const AttackPatternMatrixContainer = createRefetchContainer(
  AttackPatternMatrixComponent,
  {
    data: ReportAttackPatternsFragment,
  },
  reportKnowledgeAttackPatternsGraphQuery,
);

class ReportKnowledgeComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `report-knowledge-${props.report.id}`;
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
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
      timeLineFilters: propOr(emptyFilterGroup, 'timeLineFilters', params),
      timeLineSearchTerm: R.propOr('', 'timeLineSearchTerm', params),
    };
  }

  saveView() {
    const LOCAL_STORAGE_KEY = `report-knowledge-${this.props.report.id}`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
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

  handleAddTimeLineFilter(filterKeysSchema, key, id, op = 'eq', event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    const newFilters = constructHandleAddFilter(
      this.state.timeLineFilters,
      key,
      id,
      filterKeysSchema,
      op,
    );
    this.setState(
      {
        timeLineFilters: newFilters,
      },
      () => this.saveView(),
    );
  }

  handleRemoveTimeLineFilter(key, op = 'eq') {
    const newFilters = constructHandleRemoveFilter(
      this.state.timeLineFilters,
      key,
      op,
    );
    this.setState({ timeLineFilters: newFilters }, () => this.saveView());
  }

  handleSwitchFilterLocalMode(localFilter) {
    const newFilters = filtersAfterSwitchLocalMode(this.state.timeLineFilters, localFilter);
    this.setState({ timeLineFilters: newFilters }, () => this.saveView());
  }

  handleSwitchFilterGlobalMode() {
    const newFilters = {
      ...this.state.timeLineFilters,
      mode: this.state.timeLineFilters.mode === 'and' ? 'or' : 'and',
    };
    this.setState({ timeLineFilters: newFilters }, () => this.saveView());
  }

  handleTimeLineSearch(value) {
    this.setState({ timeLineSearchTerm: value }, () => this.saveView());
  }

  render() {
    const {
      report,
      location,
      params: { '*': mode },
      enableReferences,
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
    const defaultTypes = timeLineDisplayRelationships
      ? ['stix-core-relationship']
      : ['Stix-Core-Object'];
    const types = R.head(timeLineFilters.filters.filter((n) => n.key === 'entity_type'))
      ?.values.length > 0
      ? []
      : defaultTypes;
    let orderBy = 'created_at';
    if (timeLineFunctionalDate && timeLineDisplayRelationships) {
      orderBy = 'start_time';
    } else if (timeLineFunctionalDate) {
      orderBy = 'created';
    }
    const timeLinePaginationOptions = {
      types,
      search: timeLineSearchTerm,
      filters: timeLineFilters,
      orderBy,
      orderMode: 'desc',
    };
    return (
      <div
        style={{
          width: '100%',
          height: '100%',
        }}
        id={location.pathname.includes('matrix') ? 'parent' : 'container'}
        data-testid='report-knowledge'
      >
        {mode !== 'graph' && (
        <ContainerHeader
          container={report}
          PopoverComponent={<ReportPopover />}
          link={`/dashboard/analyses/reports/${report.id}/knowledge`}
          modes={['graph', 'timeline', 'correlation', 'matrix']}
          currentMode={mode}
          knowledge={true}
          enableSuggestions={true}
          investigationAddFromContainer={investigationAddFromContainer}
        />
        )}
        <Routes>
          <Route
            path="/graph"
            element={(
              <QueryRenderer
                query={reportKnowledgeGraphQuery}
                variables={{ id: report.id }}
                render={({ props }) => {
                  if (props && props.report) {
                    return (
                      <ReportKnowledgeGraph report={props.report} mode={mode} enableReferences={enableReferences}/>
                    );
                  }
                  return (
                    <Loader />
                  );
                }}
              />
            )}
          />
          <Route
            path="/timeline"
            element={(
              <>
                <ContentKnowledgeTimeLineBar
                  handleTimeLineSearch={this.handleTimeLineSearch.bind(this)}
                  timeLineSearchTerm={timeLineSearchTerm}
                  timeLineDisplayRelationships={timeLineDisplayRelationships}
                  handleToggleTimeLineDisplayRelationships={this.handleToggleTimeLineDisplayRelationships.bind(
                    this,
                  )}
                  timeLineFunctionalDate={timeLineFunctionalDate}
                  handleToggleTimeLineFunctionalDate={this.handleToggleTimeLineFunctionalDate.bind(
                    this,
                  )}
                  timeLineFilters={timeLineFilters}
                  handleAddTimeLineFilter={this.handleAddTimeLineFilter.bind(
                    this,
                  )}
                  handleRemoveTimeLineFilter={this.handleRemoveTimeLineFilter.bind(
                    this,
                  )}
                  handleSwitchFilterLocalMode={this.handleSwitchFilterLocalMode.bind(this)}
                  handleSwitchFilterGlobalMode={this.handleSwitchFilterGlobalMode.bind(this)}
                />
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
                    return (
                      <Loader
                        variant={LoaderVariant.inElement}
                        withTopMargin={false}
                      />
                    );
                  }}
                />
              </>
            )}
          />
          <Route
            path="/correlation"
            element={(
              <QueryRenderer
                query={reportKnowledgeCorrelationQuery}
                variables={{ id: report.id }}
                render={({ props }) => {
                  if (props && props.report) {
                    return <ReportKnowledgeCorrelation report={props.report} />;
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={false}
                    />
                  );
                }}
              />
            )}
          />
          <Route
            path="/matrix"
            element={(
              <QueryRenderer
                query={reportKnowledgeAttackPatternsGraphQuery}
                variables={{ id: report.id }}
                render={({ props }) => {
                  if (props && props.report) {
                    return (
                      <AttackPatternMatrixContainer
                        data={props}
                        report={report}
                        currentKillChain={currentKillChain}
                        currentModeOnlyActive={currentModeOnlyActive}
                        currentColorsReversed={currentColorsReversed}
                        handleChangeKillChain={this.handleChangeKillChain.bind(this)}
                        handleToggleColorsReversed={this.handleToggleColorsReversed.bind(this)}
                        handleToggleModeOnlyActive={this.handleToggleModeOnlyActive.bind(this)}
                      />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={false}
                    />
                  );
                }}
              />
            )}
          />
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={report.id}
              />
            }
          />
        </Routes>
      </div>
    );
  }
}

ReportKnowledgeComponent.propTypes = {
  report: PropTypes.object,
  mode: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.func,
  enableReferences: PropTypes.bool,
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

export default R.compose(withRouter)(ReportKnowledge);
