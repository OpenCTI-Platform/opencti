import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import useAuth from '../../../../../utils/hooks/useAuth';
import ListLines from '../../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../../relay/environment';
import EntityStixCoreRelationshipsLinesAll, { entityStixCoreRelationshipsLinesAllQuery } from '../EntityStixCoreRelationshipsLinesAll';
import EntityStixCoreRelationshipsLinesTo, { entityStixCoreRelationshipsLinesToQuery } from '../EntityStixCoreRelationshipsLinesTo';
import EntityStixCoreRelationshipsLinesFrom, { entityStixCoreRelationshipsLinesFromQuery } from '../EntityStixCoreRelationshipsLinesFrom';
import ToolBar from '../../../data/ToolBar';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import { KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from '../StixCoreRelationshipCreationFromEntity';
import Security from '../../../../../utils/Security';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes, isStixCyberObservables } from '../../../../../utils/stixTypeUtils';
import { PaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { DataColumns, PaginationOptions } from '../../../../../components/list_lines';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { CreateRelationshipContext, useInitCreateRelationshipContext } from '../CreateRelationshipContextProvider';

interface EntityStixCoreRelationshipsRelationshipsViewProps {
  entityId: string;
  entityLink: string;
  defaultStartTime?: string;
  defaultStopTime?: string;
  stixCoreObjectTypes?: string[];
  relationshipTypes: string[];
  localStorage: PaginationLocalStorage<PaginationOptions>;
  currentView: string;
  allDirections?: boolean;
  isRelationReversed?: boolean;
  enableContextualView: boolean;
  enableEntitiesView?: boolean;
  enableNestedView?: boolean;
  paddingRightButtonAdd?: number;
  role?: string;
  handleChangeView?: (viewMode: string) => void;
  allowCreation?: boolean;
  isCoverage?: boolean;
}

const EntityStixCoreRelationshipsRelationshipsView: FunctionComponent<EntityStixCoreRelationshipsRelationshipsViewProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
  localStorage,
  relationshipTypes = [],
  stixCoreObjectTypes = [],
  role,
  isRelationReversed,
  allDirections = true,
  currentView,
  enableNestedView,
  enableContextualView,
  enableEntitiesView = true,
  paddingRightButtonAdd = null,
  handleChangeView,
  allowCreation = true,
  isCoverage = false,
}) => {
  const { viewStorage, helpers: storageHelpers, localStorageKey } = localStorage;
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
    view,
  } = viewStorage;
  const { setState: setCreateRelationshipContext } = useContext(CreateRelationshipContext);

  const { platformModuleHelpers } = useAuth();
  const isObservables = isStixCyberObservables(stixCoreObjectTypes);
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const dataColumns: DataColumns = isCoverage ? {
    [isObservables ? 'observable_value' : 'name']: {
      label: isObservables ? 'Value' : 'Name',
      width: '30%',
      isSortable: false,
    },
    coverage_information: {
      label: 'Coverage',
      width: '15%',
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    creator: {
      label: 'Creators',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    start_time: {
      label: 'Start time',
      width: '8%',
      isSortable: true,
    },
    stop_time: {
      label: 'Stop time',
      width: '8%',
      isSortable: true,
    },
    confidence: {
      label: 'Confidence',
      isSortable: true,
      width: '7%',
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
      width: '8%',
    },
  } : {
    relationship_type: {
      label: 'Relationship type',
      width: '8%',
      isSortable: true,
    },
    entity_type: {
      label: 'Entity type',
      width: '10%',
      isSortable: false,
    },
    [isObservables ? 'observable_value' : 'name']: {
      label: isObservables ? 'Value' : 'Name',
      width: '20%',
      isSortable: false,
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
    start_time: {
      label: 'Start time',
      width: '8%',
      isSortable: true,
    },
    stop_time: {
      label: 'Stop time',
      width: '8%',
      isSortable: true,
    },
    created_at: {
      label: 'Platform creation date',
      width: '8%',
      isSortable: true,
    },
    confidence: {
      label: 'Confidence',
      isSortable: true,
      width: '6%',
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
      width: '8%',
    },
  };

  // Filters due to screen context
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const predefinedFilters = [{ key: 'relationship_type', values: relationshipTypes }];
  if (allDirections) {
    predefinedFilters.push({ key: 'fromOrToId', values: [entityId] });
    predefinedFilters.push({ key: 'elementWithTargetTypes', values: stixCoreObjectTypes });
  } else if (isRelationReversed) {
    predefinedFilters.push({ key: 'toId', values: [entityId] });
    if (role) predefinedFilters.push({ key: 'toRole', values: [role] });
    predefinedFilters.push({ key: 'fromTypes', values: stixCoreObjectTypes });
  } else {
    predefinedFilters.push({ key: 'fromId', values: [entityId] });
    if (role) predefinedFilters.push({ key: 'fromRole', values: [role] });
    predefinedFilters.push({ key: 'toTypes', values: stixCoreObjectTypes });
  }
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: predefinedFilters,
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const paginationOptions = {
    search: searchTerm,
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'relationship_type',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: contextFilters,
  };

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
    stixCoreObjectTypes: stixCoreObjectTypes.length
      ? stixCoreObjectTypes
      : ['Stix-Core-Object'],
    relationshipTypes,
    handleReverseRelation,
    connectionKey: 'Pagination_stixCoreRelationships',
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
        handleSearch={!isCoverage && storageHelpers.handleSearch}
        handleAddFilter={!isCoverage && storageHelpers.handleAddFilter}
        handleRemoveFilter={!isCoverage && storageHelpers.handleRemoveFilter}
        handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
        displayImport={true}
        secondaryAction={true}
        iconExtension={true}
        keyword={searchTerm}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        numberOfElements={numberOfElements}
        filters={filters}
        availableEntityTypes={relationshipTypes}
        availableRelationshipTypes={relationshipTypes}
        handleToggleExports={!isCoverage && storageHelpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_id: entityId, entity_type: 'stix-core-relationship' }}
        noPadding={true}
        handleChangeView={!isCoverage && (handleChangeView || storageHelpers.handleChangeView)}
        enableNestedView={enableNestedView}
        enableContextualView={enableContextualView}
        disableCards={true}
        paginationOptions={paginationOptions}
        enableEntitiesView={enableEntitiesView}
        currentView={finalView}
        entityTypes={['stix-core-relationship']}
      >
        <QueryRenderer
          query={

            allDirections
              ? entityStixCoreRelationshipsLinesAllQuery
              : isRelationReversed
                ? entityStixCoreRelationshipsLinesToQuery
                : entityStixCoreRelationshipsLinesFromQuery
          }
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: unknown }) =>

            (allDirections ? (
              <EntityStixCoreRelationshipsLinesAll
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                entityId={entityId}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                onToggleEntity={onToggleEntity}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                selectAll={selectAll}
                isCoverage={isCoverage}
              />
            ) : isRelationReversed ? (
              <EntityStixCoreRelationshipsLinesTo
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                onToggleEntity={onToggleEntity}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                selectAll={selectAll}
                isCoverage={isCoverage}
              />
            ) : (
              <EntityStixCoreRelationshipsLinesFrom
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                onToggleEntity={onToggleEntity}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                selectAll={selectAll}
                isCoverage={isCoverage}
              />
            ))
          }
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
        type="stix-core-relationship"
      />

      {allowCreation && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={entityId}
            allowedRelationshipTypes={relationshipTypes}
            isRelationReversed={reversedRelation}
            handleReverseRelation={handleReverseRelation}
            targetStixDomainObjectTypes={computeTargetStixDomainObjectTypes(stixCoreObjectTypes)}
            targetStixCyberObservableTypes={computeTargetStixCyberObservableTypes(stixCoreObjectTypes)}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            paginationOptions={paginationOptions}
            paddingRight={paddingRightButtonAdd ?? 220}
            currentView={finalView}
            isCoverage={isCoverage}
          />
        </Security>
      )}
    </>
  );
};

export default EntityStixCoreRelationshipsRelationshipsView;
