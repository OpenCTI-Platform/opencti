import React, { FunctionComponent, Suspense, useState } from 'react';
import { PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import {
  StixCoreObjectSharingListFragment$data,
  StixCoreObjectSharingListFragment$key,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectSharingListFragment.graphql';
import { objectOrganizationFragment } from '@components/common/stix_core_objects/StixCoreObjectSharingList';
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

interface StixCoreObjectSharedOrganisationsLoaderProps {
  queryRef: PreloadedQuery<ContainerAddStixCoreObjectsLinesQuery>
  containerId: string
  buildColumns: () => DataColumns
  knowledgeGraph?: boolean
  selectedElements: ReadonlyArray<{
    readonly id: string;
    readonly name: string;
  }>
  handleSelect?: (o: { id: string, name: string }) => void
  handleDeselect?: (o: { id: string, name: string }) => void
  helpers: PaginationLocalStorage['helpers']
  enableReferences?: boolean
  disableToggle?: boolean
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
  disableToggle = false,
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
      disableToggle={disableToggle}
    />
  );
};

interface StixCoreObjectSharedOrganisationsDrawerProps {
  data: StixCoreObjectSharingListFragment$key,
  onAdd?: (node: { id: string }) => void,
  onClose?: () => void,
  onDelete?: (node: { id: string }) => void,
  open: boolean,
  selectedText?: string,
  enableReferences?: boolean,
  knowledgeGraph?: boolean,
  disableEdit?: boolean,
}

const StixCoreObjectSharedOrganisationsDrawer: FunctionComponent<StixCoreObjectSharedOrganisationsDrawerProps> = ({
  data,
  onAdd,
  onClose,
  onDelete,
  open,
  selectedText,
  enableReferences = false,
  knowledgeGraph = false,
  disableEdit = false,
}) => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const {
    objectOrganization,
    id,
  } = useFragment<StixCoreObjectSharingListFragment$key>(objectOrganizationFragment, data);
  const targetStixCoreObjectTypes = ['Organization'];
  const LOCAL_STORAGE_KEY = `container-${id}-add-${targetStixCoreObjectTypes}`;
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
  const [selectedElements, setSelectedElements] = useState<NonNullable<StixCoreObjectSharingListFragment$data['objectOrganization']>>(objectOrganization ?? []);
  const handleSelect = (node: { id: string, name: string }) => {
    setSelectedElements([
      ...selectedElements,
      { id: node.id, name: node.name },
    ]);
    if (typeof onAdd === 'function') onAdd(node);
  };
  const handleDeselect = (node: { id: string }) => {
    setSelectedElements(selectedElements.filter((e) => e.id !== node.id));
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
        label: 'Name',
        width: '32%',
        isSortable: true,
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
              containerId={id}
              buildColumns={buildColumns}
              knowledgeGraph={knowledgeGraph}
              selectedElements={selectedElements}
              handleSelect={handleSelect}
              handleDeselect={handleDeselect}
              helpers={helpers}
              enableReferences={enableReferences}
              disableToggle={disableEdit}
            />
          </Suspense>
        )}
      </ListLines>
    </Drawer>
  );
};

export default StixCoreObjectSharedOrganisationsDrawer;
