import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { ContainerStixCoreObjectsMappingLineDummy, } from './ContainerStixCoreObjectsMappingLine';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixCoreObjectsMappingLines, {
  containerStixCoreObjectsMappingLinesQuery,
} from './ContainerStixCoreObjectsMappingLines';
import useAuth from '../../../../utils/hooks/useAuth';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '15px 0 0 0',
  },
}));

const ContainerStixCoreObjectsMapping = ({
  container,
  height,
  addMapping,
  contentMappingData,
  contentMapping,
  openDrawer,
  selectedText,
  handleClose,
}) => {
  const classes = useStyles();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const LOCAL_STORAGE_KEY = `view-container-${container.id}-stixCoreObjectsMapping`;
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      filters: {},
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
    },
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
  } = helpers;

  const buildColumns = () => {
    return {
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
        label: 'Creation',
        width: '12%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '10%',
        isSortable: isRuntimeSort,
      },
      mapping: {
        label: 'Mapping',
        width: '10%',
        isSortable: false,
      },
    };
  };
  const queryRef = useQueryLoading(
    containerStixCoreObjectsMappingLinesQuery,
    paginationOptions,
  );

  return (
      <div className={classes.container}>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={buildColumns()}
          handleSort={handleSort}
          handleSearch={handleSearch}
          handleAddFilter={handleAddFilter}
          handleRemoveFilter={handleRemoveFilter}
          iconExtension={false}
          filters={filters}
          availableFilterKeys={[
            'entity_type',
            'labelledBy',
            'markedBy',
            'created_at_start_date',
            'created_at_end_date',
            'createdBy',
          ]}
          keyword={searchTerm}
          secondaryAction={true}
          numberOfElements={numberOfElements}
          noPadding={true}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <ContainerStixCoreObjectsMappingLineDummy
                        key={idx}
                        dataColumns={buildColumns()}
                      />
                    ))}
                </>
              }
            >
              <ContainerStixCoreObjectsMappingLines
                container={container}
                queryRef={queryRef}
                paginationOptions={paginationOptions} searchTerm={searchTerm}
                dataColumns={buildColumns()}
                setNumberOfElements={handleSetNumberOfElements}
                height={height}
                contentMappingData={contentMappingData}
                contentMapping={contentMapping}
              />
            </React.Suspense>
          )}
        </ListLines>
        <ContainerAddStixCoreObjects
          containerId={container.id}
          mapping={true}
          selectedText={selectedText}
          openDrawer={openDrawer}
          handleClose={handleClose}
          defaultCreatedBy={container.createdBy ?? null}
          defaultMarkingDefinitions={(
            container.objectMarking?.edges ?? []
          ).map((n) => n.node)}
          targetStixCoreObjectTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
          confidence={container.confidence}
          paginationOptions={paginationOptions}
          onAdd={addMapping}
        />
      </div>
  );
};

export default ContainerStixCoreObjectsMapping;
