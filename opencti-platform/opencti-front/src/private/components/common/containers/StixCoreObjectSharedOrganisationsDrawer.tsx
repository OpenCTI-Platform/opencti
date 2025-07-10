import React, { FunctionComponent, Suspense, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import { PaginationLocalStorage, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import { removeEmptyFields } from '../../../../utils/utils';
import { ContainerAddStixCoreObjectsLinesQuery, ContainerAddStixCoreObjectsLinesQuery$variables } from './__generated__/ContainerAddStixCoreObjectsLinesQuery.graphql';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataColumns } from '../../../../components/list_lines';
import Drawer from '../drawer/Drawer';

type scoEdge = {
  types: string[],
  node: {
    id: string,
  }
};

interface StixCoreObjectSharedOrganisationsLoaderProps {
  queryRef: PreloadedQuery<ContainerAddStixCoreObjectsLinesQuery>
  containerId: string
  buildColumns: () => DataColumns
  knowledgeGraph?: boolean
  selectedElements: unknown[]
  handleSelect: (o: { id: string }) => void
  handleDeselect: (o: { id: string }) => void
  helpers: PaginationLocalStorage['helpers']
  enableReferences?: boolean
}

const StixCoreObjectSharedOrganisationsLoader = ({
  queryRef,
  containerId,
  buildColumns,
  knowledgeGraph,
  selectedElements,
  handleSelect,
  handleDeselect,
  helpers,
  enableReferences,
}: StixCoreObjectSharedOrganisationsLoaderProps) => {
  const data = usePreloadedQuery(containerAddStixCoreObjectsLinesQuery, queryRef);
  return (
    <ContainerAddStixCoreObjectsLines
      data={data}
      containerId={containerId}
      dataColumns={buildColumns()}
      initialLoading={data === null}
      knowledgeGraph={knowledgeGraph}
      containerStixCoreObjects={selectedElements}
      onAdd={handleSelect}
      onDelete={handleDeselect}
      setNumberOfElements={helpers.handleSetNumberOfElements}
      enableReferences={enableReferences}
      onLabelClick={helpers.handleAddFilter}
    />
  );
};

interface StixCoreObjectSharedOrganisationsDrawerProps {
  stixCoreObjectId: string,
  sharedOrganisations: unknown[],
  onAdd?: (node: { id: string }) => void,
  onClose?: () => void,
  onDelete?: (node: { id: string }) => void,
  open: boolean,
  selectedText?: string,
  enableReferences?: boolean | undefined,
  knowledgeGraph?: boolean | undefined,
}

const StixCoreObjectSharedOrganisationsDrawer: FunctionComponent<StixCoreObjectSharedOrganisationsDrawerProps> = ({
  stixCoreObjectId,
  sharedOrganisations,
  onAdd,
  onClose,
  onDelete,
  open,
  selectedText,
  enableReferences = false,
  knowledgeGraph = false,
}) => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const targetStixCoreObjectTypes = ['Organization'];
  const LOCAL_STORAGE_KEY = `container-${stixCoreObjectId}-add-${targetStixCoreObjectTypes}`;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<
  ContainerAddStixCoreObjectsLinesQuery$variables
  >(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: '_score',
      orderAsc: false,
      filters: emptyFilterGroup,
      types: targetStixCoreObjectTypes,
    },
    true,
  );
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    numberOfElements,
  } = viewStorage;
  const [selectedElements, setSelectedElements] = useState<scoEdge[]>(sharedOrganisations as scoEdge[]);
  const handleSelect = (node: { id: string }) => {
    setSelectedElements([
      ...selectedElements,
      { node, types: ['manual'] },
    ]);
    if (typeof onAdd === 'function') onAdd(node);
  };
  const handleDeselect = (node: { id: string }) => {
    setSelectedElements(selectedElements.filter((e) => e.node.id !== node.id));
    if (typeof onDelete === 'function') onDelete(node);
  };
  const keyword = (searchTerm ?? '').length === 0 ? selectedText : searchTerm;
  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '32%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeFieldEnable(),
      },
      objectLabel: {
        label: 'Labels',
        width: '22%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
        isSortable: isRuntimeFieldEnable(),
      },
    };
  };
  const { count: _, ...paginationOptionsNoCount } = paginationOptions;
  const searchPaginationOptions = removeEmptyFields({
    ...paginationOptionsNoCount,
    search: keyword,
  });
  const queryRef = useQueryLoading<ContainerAddStixCoreObjectsLinesQuery>(containerAddStixCoreObjectsLinesQuery, { count: 100, ...searchPaginationOptions });

  return (
    <Drawer
      open={open}
      title={t_i18n('Organizations')}
      onClose={onClose}
    >
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={buildColumns()}
        handleSearch={helpers.handleSearch}
        keyword={keyword}
        handleSort={helpers.handleSort}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        disableCards={true}
        filters={filters}
        paginationOptions={searchPaginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
        parametersWithPadding={true}
        disableExport={true}
        availableEntityTypes={targetStixCoreObjectTypes}
        entityTypes={targetStixCoreObjectTypes}
      >
        {(queryRef) && (
          <Suspense>
            <StixCoreObjectSharedOrganisationsLoader
              queryRef={queryRef}
              containerId={stixCoreObjectId}
              buildColumns={buildColumns}
              knowledgeGraph={knowledgeGraph}
              selectedElements={selectedElements}
              handleSelect={handleSelect}
              handleDeselect={handleDeselect}
              helpers={helpers}
              enableReferences={enableReferences}
            />
          </Suspense>
        )}
      </ListLines>
    </Drawer>
  );
};

export default StixCoreObjectSharedOrganisationsDrawer;
