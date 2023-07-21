import * as R from 'ramda';
import React, { FunctionComponent } from 'react';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import ListLines from '../../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../../relay/environment';
import EntityStixCoreRelationshipsLinesAll, {
  entityStixCoreRelationshipsLinesAllQuery,
} from '../EntityStixCoreRelationshipsLinesAll';
import EntityStixCoreRelationshipsLinesTo, {
  entityStixCoreRelationshipsLinesToQuery,
} from '../EntityStixCoreRelationshipsLinesTo';
import EntityStixCoreRelationshipsLinesFrom, {
  entityStixCoreRelationshipsLinesFromQuery,
} from '../EntityStixCoreRelationshipsLinesFrom';
import ToolBar from '../../../data/ToolBar';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import { cleanFilters, convertFilters } from '../../../../../utils/ListParameters';
import { KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from '../StixCoreRelationshipCreationFromEntity';
import Security from '../../../../../utils/Security';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes, isStixCyberObservables } from '../../../../../utils/stixTypeUtils';
import { PaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import { Filters, PaginationOptions } from '../../../../../components/list_lines';
import { ModuleHelper } from '../../../../../utils/platformModulesHelper';

interface EntityStixCoreRelationshipsRelationshipsViewProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string
  stixCoreObjectTypes: string[]
  relationshipTypes: string[]
  localStorage: PaginationLocalStorage<PaginationOptions>
  currentView: string
  allDirections?: boolean
  isRelationReversed?: boolean
  enableContextualView: boolean
  enableNestedView?: boolean
  paddingRightButtonAdd?: number
  role?: string,
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
  allDirections,
  currentView,
  enableNestedView,
  enableContextualView,
  paddingRightButtonAdd = null,
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

  const availableFilterKeys = [
    'relationship_type',
    'entity_type',
    'markedBy',
    'confidence',
    'labelledBy',
    'createdBy',
    'creator',
    'created_start_date',
    'created_end_date',
  ];

  const selectedTypes = filters?.entity_type?.map((o) => o.id) ?? stixCoreObjectTypes;
  const selectedRelationshipTypes = filters?.relationship_type?.map((o) => o.id) ?? relationshipTypes;

  let paginationOptions = {
    relationship_type: selectedRelationshipTypes,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: convertFilters(
      R.omit(['relationship_type', 'entity_type'], cleanFilters(filters, availableFilterKeys)),
    ),
  } as object;

  let backgroundTaskFilters: Filters = {
    ...filters,
    entity_type:
      selectedRelationshipTypes.length > 0
        ? selectedRelationshipTypes.map((n) => ({ id: n, value: n }))
        : [
          {
            id: 'stix-core-relationship',
            value: 'stix-core-relationship',
          },
        ],
  };

  if (allDirections) {
    paginationOptions = {
      ...paginationOptions,
      elementId: entityId,
      elementWithTargetTypes: selectedTypes,
    };
    backgroundTaskFilters = {
      ...backgroundTaskFilters,
      elementId: [{ id: entityId, value: entityId }],
      elementWithTargetTypes:
        selectedTypes.length > 0
          ? selectedTypes.map((n) => ({ id: n, value: n }))
          : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
    };
  } else if (isRelationReversed) {
    paginationOptions = {
      ...paginationOptions,
      toId: entityId,
      toRole: role || null,
      fromTypes: selectedTypes,
    };
    backgroundTaskFilters = {
      ...backgroundTaskFilters,
      toId: [{ id: entityId, value: entityId }],
      fromTypes:
        selectedTypes.length > 0
          ? selectedTypes.map((n) => ({ id: n, value: n }))
          : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
    };
  } else {
    paginationOptions = {
      ...paginationOptions,
      fromId: entityId,
      fromRole: role || null,
      toTypes: selectedTypes,
    };
    backgroundTaskFilters = {
      ...backgroundTaskFilters,
      fromId: [{ id: entityId, value: entityId }],
      toTypes:
        selectedTypes.length > 0
          ? selectedTypes.map((n) => ({ id: n, value: n }))
          : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
    };
  }

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(localStorageKey);
  const buildColumnRelationships = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isObservables = isStixCyberObservables(stixCoreObjectTypes);
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable() ?? false;
    return {
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
        label: 'Creation date',
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
  };

  let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
  if (selectAll) {
    numberOfSelectedElements = (numberOfElements?.original ?? 0) - Object.keys(deSelectedElements || {}).length;
  }
  const finalView = currentView || view;
  return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <>
            <div>
              <ListLines
                sortBy={sortBy}
                orderAsc={orderAsc}
                dataColumns={buildColumnRelationships(platformModuleHelpers)}
                handleSort={storageHelpers.handleSort}
                handleSearch={storageHelpers.handleSearch}
                handleAddFilter={storageHelpers.handleAddFilter}
                handleRemoveFilter={storageHelpers.handleRemoveFilter}
                displayImport={true}
                secondaryAction={true}
                iconExtension={true}
                keyword={searchTerm}
                handleToggleSelectAll={handleToggleSelectAll}
                selectAll={selectAll}
                numberOfElements={numberOfElements}
                filters={filters}
                availableFilterKeys={availableFilterKeys}
                availableEntityTypes={stixCoreObjectTypes}
                availableRelationshipTypes={relationshipTypes}
                handleToggleExports={storageHelpers.handleToggleExports}
                openExports={openExports}
                exportEntityType="stix-core-relationship"
                noPadding={true}
                handleChangeView={storageHelpers.handleChangeView}
                enableNestedView={enableNestedView}
                enableContextualView={enableContextualView}
                disableCards={true}
                paginationOptions={paginationOptions}
                enableEntitiesView={true}
                currentView={finalView}
              >
                <QueryRenderer
                  query={
                    // eslint-disable-next-line no-nested-ternary
                    allDirections
                      ? entityStixCoreRelationshipsLinesAllQuery
                      : isRelationReversed
                        ? entityStixCoreRelationshipsLinesToQuery
                        : entityStixCoreRelationshipsLinesFromQuery
                  }
                  variables={{ count: 25, ...paginationOptions }}
                  render={({ props }: { props: unknown }) =>
                    /* eslint-disable-next-line no-nested-ternary,implicit-arrow-linebreak */
                    (allDirections ? (
                      <EntityStixCoreRelationshipsLinesAll
                        data={props}
                        paginationOptions={paginationOptions}
                        entityLink={entityLink}
                        entityId={entityId}
                        dataColumns={buildColumnRelationships(platformModuleHelpers)}
                        initialLoading={props === null}
                        setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                        onToggleEntity={onToggleEntity}
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        selectAll={selectAll}
                      />
                    ) : isRelationReversed ? (
                      <EntityStixCoreRelationshipsLinesTo
                        data={props}
                        paginationOptions={paginationOptions}
                        entityLink={entityLink}
                        dataColumns={buildColumnRelationships(platformModuleHelpers)}
                        initialLoading={props === null}
                        setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                        onToggleEntity={onToggleEntity}
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        selectAll={selectAll}
                      />
                    ) : (
                      <EntityStixCoreRelationshipsLinesFrom
                        data={props}
                        paginationOptions={paginationOptions}
                        entityLink={entityLink}
                        dataColumns={buildColumnRelationships(platformModuleHelpers)}
                        initialLoading={props === null}
                        setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                        onToggleEntity={onToggleEntity}
                        selectedElements={selectedElements}
                        deSelectedElements={deSelectedElements}
                        selectAll={selectAll}
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
                filters={backgroundTaskFilters}
                search={searchTerm}
                handleClearSelectedElements={handleClearSelectedElements}
                variant="medium"
              />
            </div>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <StixCoreRelationshipCreationFromEntity
                entityId={entityId}
                allowedRelationshipTypes={relationshipTypes}
                isRelationReversed={isRelationReversed}
                targetStixDomainObjectTypes={computeTargetStixDomainObjectTypes(stixCoreObjectTypes)}
                targetStixCyberObservableTypes={computeTargetStixCyberObservableTypes(stixCoreObjectTypes)}
                defaultStartTime={defaultStartTime}
                defaultStopTime={defaultStopTime}
                paginationOptions={paginationOptions}
                paddingRight={paddingRightButtonAdd ?? 220}
              />
            </Security>
          </>
        )}
      </UserContext.Consumer>
  );
};

export default EntityStixCoreRelationshipsRelationshipsView;
