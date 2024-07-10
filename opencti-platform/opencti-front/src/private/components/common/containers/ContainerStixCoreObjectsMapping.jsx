import React from 'react';
import { ContainerStixCoreObjectsMappingLineDummy } from './ContainerStixCoreObjectsMappingLine';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCoreObjectsMappingLines, { containerStixCoreObjectsMappingLinesQuery } from './ContainerStixCoreObjectsMappingLines';
import useAuth from '../../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const ContainerStixCoreObjectsMapping = ({
  container,
  height,
  contentMappingData,
  contentMappingCount,
  enableReferences,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const LOCAL_STORAGE_KEY = `container-${container.id}-stixCoreObjectsMapping`;
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      types: ['Stix-Core-Object'],
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      view: 'mapping',
    },
    true,
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;
  const {
    handleRemoveFilter,
    handleSearch,
    handleSort,
    handleAddFilter,
    handleSetNumberOfElements,
    handleSwitchLocalMode,
    handleSwitchGlobalMode,
  } = helpers;

  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '15%',
      isSortable: true,
    },
    value: {
      label: 'Value',
      width: '30%',
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    created_at: {
      label: 'Platform creation date',
      width: '12%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    mapping: {
      label: 'Mapping',
      width: '8%',
      isSortable: false,
    },
  };

  const queryRef = useQueryLoading(
    containerStixCoreObjectsMappingLinesQuery,
    paginationOptions,
  );

  return (
    <div>
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        handleAddFilter={handleAddFilter}
        handleRemoveFilter={handleRemoveFilter}
        handleSwitchGlobalMode={handleSwitchGlobalMode}
        handleSwitchLocalMode={handleSwitchLocalMode}
        iconExtension={false}
        filters={filters}
        availableEntityTypes={['Stix-Core-Object']}
        keyword={searchTerm}
        secondaryAction={true}
        numberOfElements={numberOfElements}
        noPadding={true}
        disableCards
      >
        {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array(20)
                .fill(0)
                .map((_, idx) => (
                  <ContainerStixCoreObjectsMappingLineDummy
                    key={idx}
                    dataColumns={dataColumns}
                  />
                ))}
            </>
                  }
        >
          <ContainerStixCoreObjectsMappingLines
            container={container}
            queryRef={queryRef}
            paginationOptions={paginationOptions}
            searchTerm={searchTerm}
            dataColumns={dataColumns}
            setNumberOfElements={handleSetNumberOfElements}
            height={height}
            contentMappingData={contentMappingData}
            contentMappingCount={contentMappingCount}
            enableReferences={enableReferences}
          />
        </React.Suspense>
        )}
      </ListLines>
    </div>
  );
};

export default ContainerStixCoreObjectsMapping;
