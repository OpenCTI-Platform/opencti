import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import useAuth from '../../../../../utils/hooks/useAuth';
import ListLines from '../../../../../components/list_lines/ListLines';
import ToolBar from '../../../data/ToolBar';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsEntitiesViewLines from './EntityStixCoreRelationshipsEntitiesViewLines';
import { useFormatter } from '../../../../../components/i18n';
import { KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from '../StixCoreRelationshipCreationFromEntity';
import Security from '../../../../../utils/Security';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes, isStixCoreObjects, isStixCyberObservables } from '../../../../../utils/stixTypeUtils';
import { PaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { DataColumns, PaginationOptions } from '../../../../../components/list_lines';
import { EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery$variables } from './__generated__/EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery.graphql';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import { Filter, FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { CreateRelationshipContext, useInitCreateRelationshipContext } from '../CreateRelationshipContextProvider';

interface EntityStixCoreRelationshipsEntitiesViewProps {
  entityId: string;
  defaultStartTime?: string;
  defaultStopTime?: string;
  localStorage: PaginationLocalStorage<PaginationOptions>;
  relationshipTypes: string[];
  stixCoreObjectTypes?: string[];
  isRelationReversed: boolean;
  currentView: string;
  enableNestedView?: boolean;
  enableContextualView: boolean;
  paddingRightButtonAdd?: number;
  handleChangeView?: (viewMode: string) => void;
}

const EntityStixCoreRelationshipsEntitiesView: FunctionComponent<
  EntityStixCoreRelationshipsEntitiesViewProps
> = ({
  entityId,
  defaultStartTime,
  defaultStopTime,
  localStorage,
  relationshipTypes,
  stixCoreObjectTypes = ['Stix-Core-Object'],
  isRelationReversed,
  currentView,
  enableNestedView,
  enableContextualView,
  paddingRightButtonAdd = null,
  handleChangeView,
}) => {
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    helpers: storageHelpers,
    localStorageKey,
  } = localStorage;
  const {
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    view,
    numberOfElements,
    openExports,
  } = viewStorage;
  const { setState: setCreateRelationshipContext } = useContext(CreateRelationshipContext);
  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const isObservables = isStixCyberObservables(stixCoreObjectTypes);
  const dataColumns: DataColumns = {
    entity_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
    },
    [isObservables ? 'observable_value' : 'name']: {
      label: isObservables ? 'Value' : 'Name',
      width: '20%',

      isSortable: isStixCoreObjects(stixCoreObjectTypes)
        ? false
        : isObservables
          ? isRuntimeSort
          : true,
    },
    createdBy: {
      label: 'Author',
      width: '10%',
      isSortable: isRuntimeSort,
    },
    creator: {
      label: 'Creators',
      width: '10%',
      isSortable: isRuntimeSort,
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
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
      width: '10%',
    },
  };

  // Filters due to screen context
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, stixCoreObjectTypes.length > 0 ? stixCoreObjectTypes : ['Stix-Core-Object']);

  const stixCoreObjectFilter: Filter[] = stixCoreObjectTypes.length > 0
    ? [{ key: 'entity_type', operator: 'eq', mode: 'or', values: stixCoreObjectTypes }]
    : [];
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      ...stixCoreObjectFilter,
      { key: 'regardingOf',
        operator: 'eq',
        mode: 'and',
        values: [
          { key: 'id', values: [entityId], operator: 'eq', mode: 'or' },
          { key: 'relationship_type', values: relationshipTypes, operator: 'eq', mode: 'or' },
        ] as unknown as string[], // Workaround for typescript waiting for better solution
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: sortBy && sortBy in dataColumns && dataColumns[sortBy].isSortable ? sortBy : 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: contextFilters,
  } as unknown as EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery$variables; // Because of FilterMode

  const {
    selectedElements,
    numberOfSelectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(localStorageKey);

  const [reversedRelation, setReversedRelation] = useState(isRelationReversed);
  const handleReverseRelation = () => {
    setReversedRelation(!reversedRelation);
  };

  useInitCreateRelationshipContext({
    reversed: false,
    stixCoreObjectTypes,
    relationshipTypes,
    connectionKey: 'Pagination_stixCoreObjects',
    handleReverseRelation,
  });

  useEffect(() => {
    setCreateRelationshipContext({
      paginationOptions,
      reversed: reversedRelation,
      handleReverseRelation,
    });
  }, [reversedRelation]);
  useEffect(() => {
    setCreateRelationshipContext({
      paginationOptions,
      handleReverseRelation,
      onCreate: undefined,
    });
  }, [localStorage]);

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
        handleChangeView={handleChangeView || storageHelpers.handleChangeView}
        onToggleEntity={onToggleEntity}
        handleToggleSelectAll={handleToggleSelectAll}
        paginationOptions={paginationOptions}
        selectAll={selectAll}
        keyword={searchTerm}
        displayImport={true}
        handleToggleExports={storageHelpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_id: entityId, entity_type: 'Stix-Core-Object' }}
        iconExtension={true}
        filters={filters}
        availableRelationFilterTypes={{
          targets: isRelationReversed
            ? [
                'Position',
                'City',
                'Country',
                'Region',
                'Individual',
                'System',
                'Organization',
                'Sector',
                'Event',
                'Vulnerability',
              ]
            : [
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
                'Malware-Analysis',
              ],
        }}
        availableEntityTypes={stixCoreObjectTypes}
        availableRelationshipTypes={relationshipTypes}
        numberOfElements={numberOfElements}
        noPadding={true}
        disableCards={true}
        enableEntitiesView={true}
        enableNestedView={enableNestedView}
        enableContextualView={enableContextualView}
        currentView={finalView}
        entityTypes={stixCoreObjectTypes.length > 0 ? stixCoreObjectTypes : ['Stix-Core-Object']}
        additionalFilterKeys={{ filterKeys: ['entity_type'] }}
      >
        <EntityStixCoreRelationshipsEntitiesViewLines
          paginationOptions={paginationOptions}
          dataColumns={dataColumns}
          onToggleEntity={onToggleEntity}
          setNumberOfElements={storageHelpers.handleSetNumberOfElements}
          isRelationReversed={isRelationReversed}
          onLabelClick={storageHelpers.handleAddFilter}
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          selectAll={selectAll}
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
          allowedRelationshipTypes={relationshipTypes}
          isRelationReversed={reversedRelation}
          handleReverseRelation={handleReverseRelation}
          targetStixDomainObjectTypes={computeTargetStixDomainObjectTypes(
            stixCoreObjectTypes,
          )}
          targetStixCyberObservableTypes={computeTargetStixCyberObservableTypes(
            stixCoreObjectTypes,
          )}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
          paginationOptions={paginationOptions}
          connectionKey="Pagination_stixCoreObjects"
          paddingRight={paddingRightButtonAdd ?? 220}
          currentView={finalView}
        />
      </Security>
    </>
  );
};

export default EntityStixCoreRelationshipsEntitiesView;
