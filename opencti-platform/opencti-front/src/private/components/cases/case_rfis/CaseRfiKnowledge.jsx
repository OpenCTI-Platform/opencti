import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { Route, Routes } from 'react-router-dom';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, filtersAfterSwitchLocalMode } from '../../../../utils/filters/filtersUtils';
import CaseRfiKnowledgeGraph, { caseRfiKnowledgeGraphQuery } from './CaseRfiKnowledgeGraph';
import CaseRfiKnowledgeTimeLine, { caseRfiKnowledgeTimeLineQuery } from './CaseRfiKnowledgeTimeLine';
import CaseRfiKnowledgeCorrelation, { caseRfiKnowledgeCorrelationQuery } from './CaseRfiKnowledgeCorrelation';
import ContentKnowledgeTimeLineBar from '../../common/containers/ContainertKnowledgeTimeLineBar';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import withRouter from '../../../../utils/compat_router/withRouter';

class CaseRfiKnowledgeComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `case-rfis-knowledge-${props.caseData.id}`;
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.state = {
      currentModeOnlyActive: propOr(false, 'currentModeOnlyActive', params),
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
    const LOCAL_STORAGE_KEY = `case-rfis-knowledge-${this.props.caseData.id}`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
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
      caseData,
      location,
      params: { '*': mode },
      enableReferences,
    } = this.props;
    const {
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
          margin: 0,
          padding: 0,
        }}
        id={location.pathname.includes('matrix') ? 'parent' : 'container'}
        data-testid="case-rfi-knowledge"
      >
        {mode !== 'graph' && (
        <ContainerHeader
          container={caseData}
          link={`/dashboard/cases/rfis/${caseData.id}/knowledge`}
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
            element={
              <QueryRenderer
                query={caseRfiKnowledgeGraphQuery}
                variables={{ id: caseData.id }}
                render={({ props }) => {
                  if (props && props.caseRfi) {
                    return (
                      <CaseRfiKnowledgeGraph
                        id={caseData.id}
                        data={props.caseRfi}
                        mode={mode}
                        enableReferences={enableReferences}
                      />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={true}
                    />
                  );
                }}
              />
          }
          />
          <Route
            path="/timeline"
            element={
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
                  query={caseRfiKnowledgeTimeLineQuery}
                  variables={{ id: caseData.id, ...timeLinePaginationOptions }}
                  render={({ props }) => {
                    if (props && props.caseRfi) {
                      return (
                        <CaseRfiKnowledgeTimeLine
                          caseData={props.caseRfi}
                          dateAttribute={orderBy}
                          displayRelationships={timeLineDisplayRelationships}
                        />
                      );
                    }
                    return (
                      <Loader
                        variant={LoaderVariant.inElement}
                        withTopMargin={true}
                      />
                    );
                  }}
                />
              </>
          }
          />
          <Route
            path="/correlation"
            element={
              <QueryRenderer
                query={caseRfiKnowledgeCorrelationQuery}
                variables={{ id: caseData.id }}
                render={({ props }) => {
                  if (props && props.caseRfi) {
                    return (
                      <CaseRfiKnowledgeCorrelation
                        id={caseData.id}
                        data={props.caseRfi}
                      />
                    );
                  }
                  return (
                    <Loader
                      variant={LoaderVariant.inElement}
                      withTopMargin={true}
                    />
                  );
                }}
              />
          }
          />
          <Route
            path="/matrix"
            element={
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={caseData.id}
                entityType={caseData.entity_type}
              />
            }
          />
          <Route
            path="/relations/:relationId"
            element={
              <StixCoreRelationship
                entityId={caseData.id}
              />
            }
          />
        </Routes>
      </div>
    );
  }
}

CaseRfiKnowledgeComponent.propTypes = {
  caseData: PropTypes.object,
  enableReferences: PropTypes.bool,
  navigate: PropTypes.func,
};

const CaseRfiKnowledge = createFragmentContainer(CaseRfiKnowledgeComponent, {
  caseData: graphql`
    fragment CaseRfiKnowledge_case on CaseRfi {
      id
      entity_type
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default R.compose(withRouter)(CaseRfiKnowledge);
