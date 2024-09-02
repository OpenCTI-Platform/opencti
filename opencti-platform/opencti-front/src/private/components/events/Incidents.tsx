import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { IncidentsLinesQuery, IncidentsLinesQuery$variables } from './incidents/__generated__/IncidentsLinesQuery.graphql';
import { IncidentsLines_data$data } from './incidents/__generated__/IncidentsLines_data.graphql';
import { incidentLineFragment } from './incidents/IncidentLine';
import { incidentsLinesFragment, incidentsLinesQuery } from './incidents/IncidentsLines';
import IncidentCreation from './incidents/IncidentCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';

export const LOCAL_STORAGE_KEY = 'incidents';

const Incidents: FunctionComponent = () => {
  const { t_i18n } = useFormatter();

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['incident_type'], ['Incident']),
    },
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IncidentsLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Incident', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as IncidentsLinesQuery$variables;
  const queryRef = useQueryLoading<IncidentsLinesQuery>(
    incidentsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 20 },
    incident_type: { percentWidth: 8 },
    severity: { percentWidth: 8 },
    objectAssignee: { percentWidth: 12, isSortable: isRuntimeSort },
    creator: { percentWidth: 11, isSortable: isRuntimeSort },
    objectLabel: { percentWidth: 15 },
    created: { percentWidth: 10 },
    x_opencti_workflow_id: { percentWidth: 8 },
    objectMarking: { percentWidth: 8, isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: incidentsLinesQuery,
    linesFragment: incidentsLinesFragment,
    queryRef,
    nodePath: ['incidents', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<IncidentsLinesQuery>;

  return (
    <div data-testid='incident-page'>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Events') }, { label: t_i18n('Incidents'), current: true }]} />
      {queryRef && (
        <DataTable
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          preloadedPaginationProps={preloadedPaginationProps}
          resolvePath={(data: IncidentsLines_data$data) => data.incidents?.edges?.map((n) => n?.node)}
          dataColumns={dataColumns}
          lineFragment={incidentLineFragment}
          toolbarFilters={contextFilters}
          exportContext={{ entity_type: 'Incident' }}
          availableEntityTypes={['Incident']}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <IncidentCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IncidentCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </div>
  );
};

export default Incidents;
