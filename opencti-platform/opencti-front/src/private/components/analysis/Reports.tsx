import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './reports/ReportsLines';
import ReportCreation from './reports/ReportCreation';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import {
  ReportsLinesPaginationQuery,
  ReportsLinesPaginationQuery$variables,
} from './reports/__generated__/ReportsLinesPaginationQuery.graphql';
import { Filters } from '../../../components/list_lines';
import { ModuleHelper } from '../../../utils/platformModulesHelper';
import { ReportLine_node$data } from './reports/__generated__/ReportLine_node.graphql';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { ReportLineDummy } from './reports/ReportLine';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const LOCAL_STORAGE_KEY = 'view-reports';

interface ReportsProps {
  objectId: string,
  authorId: string,
  onChangeOpenExports: () => void,
  match: { params: { reportType: string } },
}

const Reports: FunctionComponent<ReportsProps> = ({
  objectId,
  authorId,
  onChangeOpenExports,
}) => {
  const additionnalFilters = [];
  if (authorId) {
    additionnalFilters.push({
      key: 'createdBy',
      values: [authorId],
      operator: 'eq',
      filterMode: 'or',
    });
  }
  if (objectId) {
    additionnalFilters.push({
      key: 'objectContains',
      values: [objectId],
      operator: 'eq',
      filterMode: 'or',
    });
  }

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ReportsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
    filters: {} as Filters,
    searchTerm: '',
    sortBy: 'published',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
  }, additionnalFilters);
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
  } = useEntityToggle<ReportLine_node$data>(
    'view-reports',
  );

  const queryRef = useQueryLoading<ReportsLinesPaginationQuery>(
    reportsLinesQuery,
    paginationOptions,
  );

  const renderLines = (helper: ModuleHelper | undefined) => {
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = (numberOfElements?.original ?? 0)
        - Object.keys(deSelectedElements || {}).length;
    }
    let renderFilters = filters;
    renderFilters = { ...renderFilters, entity_type: [{ id: 'Report', value: 'Report' }] };

    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Title',
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
        isSortable: isRuntimeSort ?? false,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort ?? false,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      published: {
        label: 'Date',
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
        isSortable: isRuntimeSort ?? false,
        width: '8%',
      },
    };

    return (
      <ExportContextProvider>
              <div>
                <ListLines
                  sortBy={sortBy}
                  orderAsc={orderAsc}
                  dataColumns={dataColumns}
                  handleSort={storageHelpers.handleSort}
                  handleSearch={storageHelpers.handleSearch}
                  handleAddFilter={storageHelpers.handleAddFilter}
                  handleRemoveFilter={storageHelpers.handleRemoveFilter}
                  handleToggleExports={storageHelpers.handleToggleExports}
                  openExports={openExports}
                  handleToggleSelectAll={handleToggleSelectAll}
                  selectAll={selectAll}
                  noPadding={typeof onChangeOpenExports === 'function'}
                  exportEntityType="Report"
                  exportContext={exportContext}
                  keyword={searchTerm}
                  redirectionMode={redirectionMode}
                  handleSwitchRedirectionMode={storageHelpers.handleSetRedirectionMode}
                  filters={filters}
                  paginationOptions={paginationOptions}
                  numberOfElements={numberOfElements}
                  iconExtension={true}
                  availableFilterKeys={[
                    'report_types',
                    'x_opencti_workflow_id',
                    'labelledBy',
                    'createdBy',
                    'creator',
                    'markedBy',
                    'confidence',
                    'published_start_date',
                    'published_end_date',
                  ]}
                >
                  {queryRef && (
                    <React.Suspense
                      fallback={
                        <>
                          {Array(20)
                            .fill(0)
                            .map((idx) => (
                              <ReportLineDummy
                                key={idx}
                                dataColumns={dataColumns}
                              />
                            ))}
                        </>
                      }
                    >
                      <ReportsLines
                        queryRef={queryRef}
                        paginationOptions={paginationOptions}
                        dataColumns={dataColumns}
                        onLabelClick={storageHelpers.handleAddFilter}
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        onToggleEntity={onToggleEntity}
                        selectAll={selectAll}
                        setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                        redirectionMode={redirectionMode}
                      />
                      <ToolBar
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        numberOfSelectedElements={numberOfSelectedElements}
                        selectAll={selectAll}
                        search={searchTerm}
                        filters={renderFilters}
                        handleClearSelectedElements={handleClearSelectedElements}
                        type="Report"
                      />
                    </React.Suspense>
                  )}
                </ListLines>
              </div>
      </ExportContextProvider>
    );
  };

  return (
    <UserContext.Consumer>
      {({ helper }) => (
        <div>
          {renderLines(helper)}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ReportCreation paginationOptions={paginationOptions} />
          </Security>
        </div>
      )}
    </UserContext.Consumer>
  );
};

export default Reports;
