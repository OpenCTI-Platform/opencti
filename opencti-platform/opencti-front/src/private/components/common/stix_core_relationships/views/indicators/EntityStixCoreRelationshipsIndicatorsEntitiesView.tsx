import React, { FunctionComponent } from 'react';
import ListLines from '../../../../../../components/list_lines/ListLines';
import ToolBar from '../../../../data/ToolBar';
import useEntityToggle from '../../../../../../utils/hooks/useEntityToggle';
import { useFormatter } from '../../../../../../components/i18n';
import StixDomainObjectIndicatorsLines, { stixDomainObjectIndicatorsLinesQuery } from '../../../../observations/indicators/StixDomainObjectIndicatorsLines';
import Security from '../../../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from '../../StixCoreRelationshipCreationFromEntity';
import { PaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { DataColumns, PaginationOptions } from '../../../../../../components/list_lines';
import { StixDomainObjectIndicatorsLinesQuery$data } from '../../../../observations/indicators/__generated__/StixDomainObjectIndicatorsLinesQuery.graphql';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { QueryRenderer } from '../../../../../../relay/environment';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../../utils/filters/filtersHelpers-types';

interface EntityStixCoreRelationshipsIndicatorsEntitiesViewProps {
  entityId: string
  relationshipTypes: string[]
  defaultStartTime: string
  defaultStopTime: string
  localStorage: PaginationLocalStorage<PaginationOptions>
  isRelationReversed: boolean
  currentView: string
  enableContextualView: boolean,
}

const EntityStixCoreRelationshipsIndicatorsEntitiesView: FunctionComponent<EntityStixCoreRelationshipsIndicatorsEntitiesViewProps> = ({
  entityId,
  relationshipTypes,
  defaultStartTime,
  defaultStopTime,
  localStorage,
  isRelationReversed,
  currentView,
  enableContextualView,
}) => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers: storageHelpers, localStorageKey } = localStorage;
  const {
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    view,
    numberOfElements,
    openExports,
  } = viewStorage;

  const availableFilterKeys = [
    'objectLabel',
    'objectMarking',
    'created',
    'valid_from',
    'valid_until',
    'x_opencti_score',
    'createdBy',
    'sightedBy',
    'x_opencti_detection',
    'based-on',
    'revoked',
    'creator_id',
    'confidence',
    'indicator_types',
    'pattern_type',
    'x_opencti_main_observable_type',
  ];

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const dataColumns: DataColumns = {
    pattern_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '25%',
      isSortable: true,
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
    },
    created_at: {
      label: 'Platform creation date',
      width: '15%',
      isSortable: true,
    },
    valid_until: {
      label: 'Valid until',
      width: '15%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
      width: '10%',
    },
  };

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Indicator']);
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Indicator'], mode: 'or', operator: 'eq' },
      {
        key: 'regardingOf',
        values: [
          { key: 'id', values: [entityId] },
          { key: 'relationship_type', values: ['indicates'] },
        ],
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: contextFilters,
  };

  const {
    numberOfSelectedElements,
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(localStorageKey);

  const finalView = currentView || view;
  return (
    <>
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
        handleChangeView={storageHelpers.handleChangeView}
        onToggleEntity={onToggleEntity}
        handleToggleSelectAll={handleToggleSelectAll}
        paginationOptions={paginationOptions}
        selectAll={selectAll}
        keyword={searchTerm}
        displayImport
        handleToggleExports={storageHelpers.handleToggleExports}
        openExports={openExports}
        iconExtension={true}
        filters={filters}
        availableFilterKeys={availableFilterKeys}
        exportContext={{ entity_id: entityId, entity_type: 'Stix-Core-Object' }}
        numberOfElements={numberOfElements}
        disableCards
        enableEntitiesView
        enableContextualView={enableContextualView}
        noPadding
        currentView={finalView}
      >
        <QueryRenderer
          query={stixDomainObjectIndicatorsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: StixDomainObjectIndicatorsLinesQuery$data }) => (
            <StixDomainObjectIndicatorsLines
              data={props}
              paginationOptions={paginationOptions}
              entityId={entityId}
              dataColumns={dataColumns}
              initialLoading={props === null}
              setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              onToggleEntity={onToggleEntity}
              selectAll={selectAll}
            />
          )}
        />
      </ListLines>
      <ToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        filters={contextFilters}
        search={searchTerm}
        handleClearSelectedElements={handleClearSelectedElements}
        variant="medium"
        warning={true}
        warningMessage={t_i18n(
          'Be careful, you are about to delete the selected entities (not the relationships)',
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          isRelationReversed={isRelationReversed}
          targetStixDomainObjectTypes={['Indicator']}
          allowedRelationshipTypes={relationshipTypes}
          paginationOptions={paginationOptions}
          openExports={openExports}
          paddingRight={220}
          connectionKey="Pagination_indicators"
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
        />
      </Security>
    </>
  );
};
export default EntityStixCoreRelationshipsIndicatorsEntitiesView;
