import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { Route, withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import AttackPatternsMatrix from '../../techniques/attack_patterns/AttackPatternsMatrix';
import { buildViewParamsFromUrlAndStorage, convertFilters, saveViewParameters } from '../../../../utils/ListParameters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import CaseRftPopover from './CaseRftPopover';
import CaseRftKnowledgeGraph, { caseRftKnowledgeGraphQuery } from './CaseRftKnowledgeGraph';
import CaseRftKnowledgeTimeLine, { caseRftKnowledgeTimeLineQuery } from './CaseRftKnowledgeTimeLine';
import CaseRftKnowledgeCorrelation, { caseRftKnowledgeCorrelationQuery } from './CaseRftKnowledgeCorrelation';
import ContentKnowledgeTimeLineBar from '../../common/containers/ContainertKnowledgeTimeLineBar';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

export const caseRftKnowledgeAttackPatternsGraphQuery = graphql`
  query CaseRftKnowledgeAttackPatternsGraphQuery($id: String!) {
    caseRft(id: $id) {
      id
      name
      x_opencti_graph_data
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

class CaseRftKnowledgeComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-case-rfts-knowledge-${props.caseData.id}`,
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
      `view-case-rfts-knowledge-${this.props.caseData.id}`,
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
      caseData,
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
    const finalFilters = convertFilters(timeLineFilters);
    const defaultTypes = timeLineDisplayRelationships
      ? ['stix-core-relationship']
      : ['Stix-Core-Object'];
    const types = R.head(finalFilters.filter((n) => n.key === 'entity_type'))?.values
      .length > 0
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
            container={caseData}
            PopoverComponent={<CaseRftPopover id={caseData.id} />}
            link={`/dashboard/cases/rfts/${caseData.id}/knowledge`}
            modes={['graph', 'content', 'timeline', 'correlation', 'matrix']}
            currentMode={mode}
            knowledge={true}
          />
        )}
        <Route
          exact
          path="/dashboard/cases/rfts/:caseId/knowledge/graph"
          render={() => (
            <QueryRenderer
              query={caseRftKnowledgeGraphQuery}
              variables={{ id: caseData.id }}
              render={({ props }) => {
                if (props && props.caseRft) {
                  return (
                    <CaseRftKnowledgeGraph
                      caseData={props.caseRft}
                      mode={mode}
                    />
                  );
                }
                return <Loader />;
              }}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/cases/rfts/:caseId/knowledge/timeline"
          render={() => (
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
              />
              <QueryRenderer
                query={caseRftKnowledgeTimeLineQuery}
                variables={{ id: caseData.id, ...timeLinePaginationOptions }}
                render={({ props }) => {
                  if (props && props.caseRft) {
                    return (
                      <CaseRftKnowledgeTimeLine
                        caseData={props.caseRft}
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
          path="/dashboard/cases/rfts/:caseId/knowledge/correlation"
          render={() => (
            <QueryRenderer
              query={caseRftKnowledgeCorrelationQuery}
              variables={{ id: caseData.id }}
              render={({ props }) => {
                if (props && props.caseRft) {
                  return (
                    <CaseRftKnowledgeCorrelation caseData={props.caseRft} />
                  );
                }
                return <Loader />;
              }}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/cases/rfts/:caseId/knowledge/matrix"
          render={() => (
            <QueryRenderer
              query={caseRftKnowledgeAttackPatternsGraphQuery}
              variables={{ id: caseData.id }}
              render={({ props }) => {
                if (props && props.caseRft) {
                  const attackPatterns = R.pipe(
                    R.map((n) => n.node),
                    R.filter((n) => n.entity_type === 'Attack-Pattern'),
                  )(props.caseRft.objects.edges);
                  return (
                    <AttackPatternsMatrix
                      entity={caseData}
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

CaseRftKnowledgeComponent.propTypes = {
  caseData: PropTypes.object,
  mode: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const CaseRftKnowledge = createFragmentContainer(CaseRftKnowledgeComponent, {
  caseData: graphql`
    fragment CaseRftKnowledge_case on CaseRft {
      id
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default R.compose(withRouter, withStyles(styles))(CaseRftKnowledge);
