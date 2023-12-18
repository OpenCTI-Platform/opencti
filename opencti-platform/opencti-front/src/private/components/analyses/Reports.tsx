import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './reports/ReportsLines';
import ReportCreation from './reports/ReportCreation';
import ToolBar from '../data/ToolBar';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { ReportsLinesPaginationQuery, ReportsLinesPaginationQuery$variables } from './reports/__generated__/ReportsLinesPaginationQuery.graphql';
import { ReportLine_node$data } from './reports/__generated__/ReportLine_node.graphql';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { ReportLineDummy } from './reports/ReportLine';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const LOCAL_STORAGE_KEY = 'reports';

const Reports: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ReportsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'published',
      orderAsc: false,
      openExports: false,
      redirectionMode: 'overview',
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
    redirectionMode,
  } = viewStorage;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<ReportLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Report', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ReportsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ReportsLinesPaginationQuery>(
    reportsLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      report_types: {
        label: 'Type',
        width: '8%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      published: {
        label: 'Publication date',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '8%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <div data-testid="report-page">
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          handleToggleExports={storageHelpers.handleToggleExports}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          exportContext={{ entity_type: 'Report' }}
          keyword={searchTerm}
          redirectionMode={redirectionMode}
          handleSwitchRedirectionMode={(value: string) => storageHelpers.handleAddProperty('redirectionMode', value)}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <ReportLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <ReportsLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                redirectionMode={redirectionMode}
              />
            </React.Suspense>
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={contextFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Report"
        />
      </div>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Reports'), current: true }]} />
      {renderLines()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Report'>
        <ReportCreation paginationOptions={queryPaginationOptions} />
      </KnowledgeSecurity>
    </ExportContextProvider>
  );
};

export default Reports;
