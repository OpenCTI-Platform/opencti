import React, { FunctionComponent, useState } from 'react';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import ReportsLines, { reportsLinesQuery } from './reports/ReportsLines';
import ReportCreation from './reports/ReportCreation';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import {
  ReportsLinesPaginationQuery$data,
  ReportsLinesPaginationQuery$variables,
} from './reports/__generated__/ReportsLinesPaginationQuery.graphql';
import { Filters } from '../../../components/list_lines';
import { ModuleHelper } from '../../../utils/platformModulesHelper';
import { ReportLine_node$data } from './reports/__generated__/ReportLine_node.graphql';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';

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
  match,
}) => {
  const [viewStorage, setViewStorage, storageHelpers] = useLocalStorage(LOCAL_STORAGE_KEY, {
    numberOfElements: { number: 0, symbol: '', original: 0 },
    filters: {} as Filters,
    searchTerm: '',
    sortBy: 'published',
    orderAsc: false,
    openExports: false,
    count: 25,
  });

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
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

  const [NotEqLocalFilterMode] = useState('and');
  const [EqLocalFilterMode] = useState('or');

  const { reportType } = match.params;

  const reportFilterClass = reportType !== 'all' && reportType !== undefined
    ? reportType.replace(/_/g, ' ')
    : '';

  const additionnalFilters = [];
  if (reportFilterClass) {
    additionnalFilters.push({
      key: 'report_types',
      values: [reportFilterClass],
      operator: 'eq',
      filterMode: 'or',
    });
  }
  if (authorId) {
    additionnalFilters.push({
      key: 'createdBy',
      values: [authorId],
      operator: 'eq',
      filterMode: 'or' });
  }
  if (objectId) {
    additionnalFilters.push({
      key: 'objectContains',
      values: [objectId],
      operator: 'eq',
      filterMode: 'or' });
  }

  const paginationOptions = localStorageToPaginationOptions<ReportsLinesPaginationQuery$variables>({
    filters,
    search: searchTerm,
    sortBy,
    orderAsc,
    additionnalFilters,
    count: 25,
  });

  const handleChangeLocalFilterMode = (key: string) => {
    if (filters) {
      const filterContent = filters[key];
      let newKey = key;
      if (key.endsWith('_or')) {
        newKey = key.replace('_or', '_and');
      } else if (key.endsWith('_and')) {
        newKey = key.replace('_and', '_or');
      }
      setViewStorage((c) => ({
        ...c,
        filters: {
          ...R.dissoc(key, filters),
          [newKey]: filterContent,
        },
      }));
    }
  };

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
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creator',
        width: '12%',
        isSortable: isRuntimeSort,
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
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
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
          handleChangeLocalFilterMode={handleChangeLocalFilterMode}
          EqLocalFilterMode={EqLocalFilterMode}
          NotEqLocalFilterMode={NotEqLocalFilterMode}
        >
          <QueryRenderer
            query={reportsLinesQuery}
            variables={{ ...paginationOptions }}
            render={({ props }: { props: ReportsLinesPaginationQuery$data }) => (
              <ReportsLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            )}
          />
        </ListLines>
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
      </div>
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
