import { SyntheticEvent, useEffect, useReducer, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ReportKnowledgeGraph, { reportKnowledgeGraphQuery } from './ReportKnowledgeGraph';
import ReportKnowledgeCorrelation, { reportKnowledgeCorrelationQuery } from './ReportKnowledgeCorrelation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import ReportKnowledgeTimeLine, { reportKnowledgeTimeLineQuery } from './ReportKnowledgeTimeLine';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, filtersAfterSwitchLocalMode } from '../../../../utils/filters/filtersUtils';
import ContentKnowledgeTimeLineBar from '../../common/containers/ContainertKnowledgeTimeLineBar';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import type { FilterDefinition } from '../../../../utils/hooks/useAuth';
import type { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import type { ReportKnowledgeGraphQuery$data } from './__generated__/ReportKnowledgeGraphQuery.graphql';
import type { ReportKnowledgeTimeLineQuery$data } from './__generated__/ReportKnowledgeTimeLineQuery.graphql';
import type { ReportKnowledgeCorrelationQuery$data } from './__generated__/ReportKnowledgeCorrelationQuery.graphql';
import type { ReportKnowledge_report$data } from './__generated__/ReportKnowledge_report.graphql';

interface ReportKnowledgeComponentState {
  currentModeOnlyActive: boolean;
  currentKillChain: string;
  timeLineDisplayRelationships: boolean;
  timeLineFunctionalDate: boolean;
  timeLineFilters: FilterGroup;
  timeLineSearchTerm: string;
}

type ReportKnowledgeComponentAction = {
  type: 'toggle-timeline-display-relationships';
} | {
  type: 'toggle-timeline-functional-date';
} | {
  type: 'add-timeline-filter';
  id: string | null;
  key: string;
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
  op: string;
} | {
  type: 'remove-timeline-filter';
  key: string;
  op: string;
} | {
  type: 'switch-filter-local-mode';
  localFilter: Filter;
} | {
  type: 'switch-filter-global-mode';
} | {
  type: 'timeline-search';
  value: string;
};

const reducer = (state: ReportKnowledgeComponentState, action: ReportKnowledgeComponentAction) => {
  switch (action.type) {
    case 'toggle-timeline-display-relationships': {
      return {
        ...state,
        timeLineDisplayRelationships: !state.timeLineDisplayRelationships,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'toggle-timeline-functional-date': {
      return {
        ...state,
        timeLineFunctionalDate: !state.timeLineFunctionalDate,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'add-timeline-filter': {
      const { key, id, filterKeysSchema, op } = action;
      const newFilters = constructHandleAddFilter(
        state.timeLineFilters,
        key,
        id,
        filterKeysSchema,
        op,
      );
      return {
        ...state,
        timeLineFilters: newFilters,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'remove-timeline-filter': {
      const { key, op } = action;
      const newFilters = constructHandleRemoveFilter(
        state.timeLineFilters,
        key,
        op,
      );
      return {
        ...state,
        timeLineFilters: newFilters!,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'switch-filter-local-mode': {
      const { localFilter } = action;
      const newFilters = filtersAfterSwitchLocalMode(state.timeLineFilters, localFilter);
      return {
        ...state,
        timeLineFilters: newFilters!,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'switch-filter-global-mode': {
      const newFilters = {
        ...state.timeLineFilters,
        mode: state.timeLineFilters.mode === 'and' ? 'or' : 'and',
      };
      return {
        ...state,
        timeLineFilters: newFilters,
      } satisfies ReportKnowledgeComponentState;
    }
    case 'timeline-search': {
      const { value } = action;
      return {
        ...state,
        timeLineSearchTerm: value,
      } satisfies ReportKnowledgeComponentState;
    }
  }
  return state;
};

interface ReportKnowledgeComponentProps {
  report: ReportKnowledge_report$data;
  enableReferences: boolean;
}

const ReportKnowledgeComponent = (props: ReportKnowledgeComponentProps) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { '*': mode = 'graph' } = useParams();
  const LOCAL_STORAGE_KEY = `report-knowledge-${props.report.id}`;
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [state, dispatch] = useReducer<
    ReportKnowledgeComponentState,
    ReturnType<typeof buildViewParamsFromUrlAndStorage>,
    [ReportKnowledgeComponentAction]
  >(reducer, buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  ), (params) => ({
    currentModeOnlyActive: params['currentModeOnlyActive'] ?? false,
    currentKillChain: params['currentKillChain'] ?? 'mitre-attack',
    timeLineDisplayRelationships: params['timeLineDisplayRelationships'] ?? false,
    timeLineFunctionalDate: params['timeLineFunctionalDate'] ?? false,
    timeLineFilters: params['timeLineFilters'] ?? emptyFilterGroup,
    timeLineSearchTerm: params['timeLineSearchTerm'] ?? '',
  }));

  const saveView = () => saveViewParameters(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
    state,
  );

  useEffect(() => {
    if (hasUnsavedChanges) {
      saveView();
      setHasUnsavedChanges(false);
    }
  }, [hasUnsavedChanges]);

  const handleToggleTimeLineDisplayRelationships = () => {
    dispatch({ type: 'toggle-timeline-display-relationships' });
    setHasUnsavedChanges(true);
  };

  const handleToggleTimeLineFunctionalDate = () => {
    dispatch({ type: 'toggle-timeline-functional-date' });
    setHasUnsavedChanges(true);
  };

  const handleAddTimeLineFilter = (
    filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
    key: string,
    id: string | null,
    op: string = 'eq',
    event?: SyntheticEvent,
  ) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    dispatch({
      type: 'add-timeline-filter',
      id,
      key,
      filterKeysSchema,
      op,
    });
    setHasUnsavedChanges(true);
  };

  const handleRemoveTimeLineFilter = (key: string, op: string = 'eq') => {
    dispatch({
      type: 'remove-timeline-filter',
      key,
      op,
    });
    setHasUnsavedChanges(true);
  };

  const handleSwitchFilterLocalMode = (localFilter: Filter) => {
    dispatch({
      type: 'switch-filter-local-mode',
      localFilter,
    });
    setHasUnsavedChanges(true);
  };

  const handleSwitchFilterGlobalMode = () => {
    dispatch({ type: 'switch-filter-global-mode' });
    setHasUnsavedChanges(true);
  };

  const handleTimeLineSearch = (value: string) => {
    dispatch({
      type: 'timeline-search',
      value,
    });
    setHasUnsavedChanges(true);
  };

  const { report, enableReferences } = props;
  const {
    timeLineFilters,
    timeLineDisplayRelationships,
    timeLineFunctionalDate,
    timeLineSearchTerm,
  } = state;

  const defaultTypes = timeLineDisplayRelationships
    ? ['stix-core-relationship']
    : ['Stix-Core-Object'];
  const types = (timeLineFilters.filters.filter((n) => n.key === 'entity_type').at(0)
    ?.values?.length ?? 0) > 0
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
        position: 'relative',
      }}
      id={location.pathname.includes('matrix') ? 'parent' : 'container'}
      data-testid="report-knowledge"
    >
      {mode !== 'graph' && (
        <ContainerHeader
          container={report}
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
              render={({ props }: { props: ReportKnowledgeGraphQuery$data }) => {
                if (props && props.report) {
                  return (
                    <ReportKnowledgeGraph
                      id={report.id}
                      mode={mode}
                      data={props.report}
                      enableReferences={enableReferences}
                    />
                  );
                }
                return (
                  <div style={{ height: '50vh' }}>
                    <Loader
                      variant={LoaderVariant.inElement}
                    />
                  </div>
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
                handleTimeLineSearch={handleTimeLineSearch}
                timeLineSearchTerm={timeLineSearchTerm}
                timeLineDisplayRelationships={timeLineDisplayRelationships}
                handleToggleTimeLineDisplayRelationships={handleToggleTimeLineDisplayRelationships}
                timeLineFunctionalDate={timeLineFunctionalDate}
                handleToggleTimeLineFunctionalDate={handleToggleTimeLineFunctionalDate}
                timeLineFilters={timeLineFilters}
                handleAddTimeLineFilter={handleAddTimeLineFilter}
                handleRemoveTimeLineFilter={handleRemoveTimeLineFilter}
                handleSwitchFilterLocalMode={handleSwitchFilterLocalMode}
                handleSwitchFilterGlobalMode={handleSwitchFilterGlobalMode}
              />
              <QueryRenderer
                query={reportKnowledgeTimeLineQuery}
                variables={{ id: report.id, ...timeLinePaginationOptions }}
                render={({ props }: { props: ReportKnowledgeTimeLineQuery$data }) => {
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
                    <div style={{ height: '50vh' }}>
                      <Loader
                        variant={LoaderVariant.inElement}
                      />
                    </div>
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
              render={({ props }: { props: ReportKnowledgeCorrelationQuery$data }) => {
                if (props && props.report) {
                  return (
                    <ReportKnowledgeCorrelation
                      id={report.id}
                      data={props.report}
                    />
                  );
                }
                return (
                  <div style={{ height: '50vh' }}>
                    <Loader
                      variant={LoaderVariant.inElement}
                    />
                  </div>
                );
              }}
            />
          )}
        />
        <Route
          path="/matrix"
          element={(
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={report.id}
              entityType={report.entity_type}
              disableExport={false}
            />
          )}
        />
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={report.id}
            />
          )}
        />
        <Route index element={<Navigate replace={true} to="graph" />} />
      </Routes>
    </div>
  );
};

const ReportKnowledge = createFragmentContainer(ReportKnowledgeComponent, {
  report: graphql`
    fragment ReportKnowledge_report on Report {
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

export default ReportKnowledge;
