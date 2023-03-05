import React, { FunctionComponent, useContext } from 'react';
import * as R from 'ramda';
import ListLines from '../../../components/list_lines/ListLines';
import ExternalReferencesLines, {
  externalReferencesLinesQuery,
} from './external_references/ExternalReferencesLines';
import ExternalReferenceCreation from './external_references/ExternalReferenceCreation';
import Security from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import {
  ExternalReferencesLinesPaginationQuery,
  ExternalReferencesLinesPaginationQuery$variables,
} from './external_references/__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { ExternalReferenceLine_node$data } from './external_references/__generated__/ExternalReferenceLine_node.graphql';
import ToolBar from '../data/ToolBar';
import { Filters } from '../../../components/list_lines';
import { ExternalReferenceLineDummy } from './external_references/ExternalReferenceLine';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-external-references';

interface ExternalReferencesProps {
  history: History;
  location: Location;
}

const ExternalReferences: FunctionComponent<ExternalReferencesProps> = () => {
  const { helper } = useContext(UserContext);
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ExternalReferencesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const { sortBy, orderAsc, searchTerm, filters, numberOfElements } = viewStorage;
  const isRuntimeSort = helper?.isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    source_name: {
      label: 'Source name',
      width: '15%',
      isSortable: true,
    },
    external_id: {
      label: 'External ID',
      width: '10%',
      isSortable: true,
    },
    url: {
      label: 'URL',
      width: '45%',
      isSortable: true,
    },
    creator: {
      label: 'Creator',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    created: {
      label: 'Creation date',
      width: '15%',
      isSortable: true,
    },
  };
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<ExternalReferenceLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<ExternalReferencesLinesPaginationQuery>(
    externalReferencesLinesQuery,
    paginationOptions,
  );
  let finalFilters = filters;
  finalFilters = R.assoc(
    'entity_type',
    [{ id: 'External-Reference', value: 'External-Reference' }],
    finalFilters,
  );
  return (
    <div>
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        displayImport={true}
        secondaryAction={true}
        filters={filters}
        keyword={searchTerm}
        iconExtension={true}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'creator',
          'created_start_date',
          'created_end_date',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <ExternalReferenceLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <>
              <ExternalReferencesLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
              <ToolBar
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                numberOfSelectedElements={numberOfSelectedElements}
                handleClearSelectedElements={handleClearSelectedElements}
                selectAll={selectAll}
                search={searchTerm}
                filters={finalFilters}
                type="External-Reference"
              />
            </>
          </React.Suspense>
        )}
      </ListLines>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ExternalReferenceCreation
          paginationOptions={paginationOptions}
          openContextual={false}
        />
      </Security>
    </div>
  );
};

export default ExternalReferences;
