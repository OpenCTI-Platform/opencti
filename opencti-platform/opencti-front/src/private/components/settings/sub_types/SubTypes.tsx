import React from 'react';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { DataSourcesLinesPaginationQuery$variables } from '../../techniques/data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypesLines, { subTypesLinesQuery } from './SubTypesLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { SubTypeLineDummy } from './SubTypesLine';
import { SubTypesLinesQuery } from './__generated__/SubTypesLinesQuery.graphql';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import ToolBar from './ToolBar';

const LOCAL_STORAGE_KEY_SUB_TYPES = 'view-sub-types';

const SubTypes = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<DataSourcesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_SUB_TYPES,
    {
      searchTerm: '',
      numberOfElements: { number: 0, symbol: '', original: 0 },
    },
  );
  const dataColumns = {
    entity_type: {
      label: 'Entity type',
      width: '30%',
      isSortable: false,
    },
    workflow_status: {
      label: 'Workflow status',
      width: '15%',
      isSortable: false,
    },
    enforce_reference: {
      label: 'Enforce reference',
      width: '15%',
      isSortable: false,
    },
    automatic_references: {
      label: 'Automatic references at file upload',
      width: '15%',
      isSortable: false,
    },
    hidden: {
      label: 'Hidden in interface',
      width: '15%',
      isSortable: false,
    },
  };
  const { searchTerm } = viewStorage;
  const queryRef = useQueryLoading<SubTypesLinesQuery>(
    subTypesLinesQuery,
    paginationOptions,
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle(LOCAL_STORAGE_KEY_SUB_TYPES);
  return (
    <ListLines
      handleSearch={helpers.handleSearch}
      keyword={searchTerm}
      dataColumns={dataColumns}
      iconExtension={true}
      selectAll={selectAll}
      handleToggleSelectAll={handleToggleSelectAll}
    >
      {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array.from(Array(20).keys()).map((idx) => (
                <SubTypeLineDummy key={idx} dataColumns={dataColumns} />
              ))}
            </>
          }
        >
          <SubTypesLines
            queryRef={queryRef}
            keyword={searchTerm}
            dataColumns={dataColumns}
            setNumberOfElements={helpers.handleSetNumberOfElements}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            selectAll={selectAll}
            onToggleEntity={onToggleEntity}
          />
          <ToolBar
            keyword={searchTerm}
            numberOfSelectedElements={numberOfSelectedElements}
            selectedElements={selectedElements}
            selectAll={selectAll}
            handleClearSelectedElements={handleClearSelectedElements}
          />
        </React.Suspense>
      )}
    </ListLines>
  );
};

export default SubTypes;
