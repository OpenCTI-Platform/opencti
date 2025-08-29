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
import IncidentKnowledgeGraph, { incidentKnowledgeGraphQuery } from './IncidentKnowledgeGraph';
import IncidentKnowledgeCorrelation, { incidentKnowledgeCorrelationQuery } from './IncidentKnowledgeCorrelation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import IncidentKnowledgeTimeLine, { incidentKnowledgeTimeLineQuery } from './IncidentKnowledgeTimeLine';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, filtersAfterSwitchLocalMode } from '../../../../utils/filters/filtersUtils';
import ContentKnowledgeTimeLineBar from '../../common/containers/ContainertKnowledgeTimeLineBar';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import withRouter from '../../../../utils/compat_router/withRouter';

class IncidentKnowledgeComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `case-incident-knowledge-${props.caseData.id}`;
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
    const LOCAL_STORAGE_KEY = `case-incident-knowledge-${this.props.caseData.id}`;
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
        data-testid='incident-response-knowledge'
      >
        {mode !== 'graph' && (
        <ContainerHeader
          container={caseData}
          link={`/dashboard/cases/incidents/${caseData.id}/knowledge`}
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
                query={incidentKnowledgeGraphQuery}
                variables={{ id: caseData.id }}
                render={({ props }) => {
                  if (props && props.caseIncident) {
                    return (
                      <IncidentKnowledgeGraph
                        id={caseData.id}
                        data={props.caseIncident}
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
              />}
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
                  query={incidentKnowledgeTimeLineQuery}
                  variables={{ id: caseData.id, ...timeLinePaginationOptions }}
                  render={({ props }) => {
                    if (props && props.caseIncident) {
                      return (
                        <IncidentKnowledgeTimeLine
                          caseData={props.caseIncident}
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
              </>}
          />
          <Route
            path="/correlation"
            element={
              <QueryRenderer
                query={incidentKnowledgeCorrelationQuery}
                variables={{ id: caseData.id }}
                render={({ props }) => {
                  if (props && props.caseIncident) {
                    return (
                      <IncidentKnowledgeCorrelation
                        data={props.caseIncident}
                        id={caseData.id}
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
              />}
          />
          <Route
            path="/matrix"
            element={
              <StixDomainObjectAttackPatterns
                stixDomainObjectId={caseData.id}
                defaultStartTime={caseData.first_seen}
                defaultStopTime={caseData.last_seen}
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

IncidentKnowledgeComponent.propTypes = {
  caseData: PropTypes.object,
  navigate: PropTypes.func,
  enableReferences: PropTypes.bool,
};

const IncidentKnowledge = createFragmentContainer(IncidentKnowledgeComponent, {
  caseData: graphql`
    fragment IncidentKnowledge_case on CaseIncident {
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

export default R.compose(withRouter)(IncidentKnowledge);
