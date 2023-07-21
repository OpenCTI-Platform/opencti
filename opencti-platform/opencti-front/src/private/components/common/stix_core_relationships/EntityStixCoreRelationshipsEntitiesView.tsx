import * as R from 'ramda';
import React, { FunctionComponent } from 'react';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import ToolBar from '../../data/ToolBar';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsEntities from './EntityStixCoreRelationshipsEntities';
import { useFormatter } from '../../../../components/i18n';
import { convertFilters } from '../../../../utils/ListParameters';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes, isStixCoreObjects, isStixCyberObservables } from '../../../../utils/stixTypeUtils';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import { PaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { Filters, PaginationOptions } from '../../../../components/list_lines';
import {
  EntityStixCoreRelationshipsEntitiesPaginationQuery$variables,
} from './__generated__/EntityStixCoreRelationshipsEntitiesPaginationQuery.graphql';

const LOCAL_STORAGE_KEY = 'view-entityStixCoreRelationshipsEntitiesView';

interface EntityStixCoreRelationshipsEntitiesViewProps {
  entityId: string
  entityLink: string
  defaultStartTime: string
  defaultStopTime: string,
  localStorage: PaginationLocalStorage<PaginationOptions>
  relationshipTypes: string[]
  stixCoreObjectTypes: string[]
  isRelationReversed: boolean,
  currentView: string
  enableNestedView?: boolean,
  enableContextualView: boolean,
  paddingRightButtonAdd?: number
}
const EntityStixCoreRelationshipsEntitiesView: FunctionComponent<EntityStixCoreRelationshipsEntitiesViewProps> = ({
  entityId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
  localStorage,
  relationshipTypes,
  stixCoreObjectTypes,
  isRelationReversed,
  currentView,
  enableNestedView,
  enableContextualView,
  paddingRightButtonAdd = null,
}) => {
  const { t } = useFormatter();
  const { viewStorage, helpers: storageHelpers } = localStorage;
  const {
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    view,
    numberOfElements,
    openExports,
  } = viewStorage;

  const selectedTypes = filters?.entity_type?.map((o) => o.id) ?? stixCoreObjectTypes;
  const selectedRelationshipTypes = filters?.relationship_type?.map((o) => o.id) ?? relationshipTypes;

  const paginationOptions = {
    types: selectedTypes,
    relationship_type: selectedRelationshipTypes,
    elementId: entityId,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: convertFilters(
      R.omit(['relationship_type', 'entity_type'], filters),
    ),
  } as unknown as EntityStixCoreRelationshipsEntitiesPaginationQuery$variables;

  let backgroundTaskFilters: Filters;
  if (selectedRelationshipTypes.length > 0) {
    backgroundTaskFilters = {
      ...filters,
      entity_type:
        selectedTypes.length > 0
          ? selectedTypes.map((n) => ({ id: n, value: n }))
          : [{ id: 'Stix-Core-Object', value: 'Stix-Core-Object' }],
      [`rel_${selectedRelationshipTypes.at(0)}.*`]: [
        { id: entityId, value: entityId },
      ],
    };
  }

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(LOCAL_STORAGE_KEY);
  const buildColumnsEntities = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isObservables = isStixCyberObservables(stixCoreObjectTypes);
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable() ?? false;
    return {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      [isObservables ? 'observable_value' : 'name']: {
        label: isObservables ? 'Value' : 'Name',
        width: '25%',
        // eslint-disable-next-line no-nested-ternary
        isSortable: isStixCoreObjects(stixCoreObjectTypes)
          ? false
          : isObservables
            ? isRuntimeSort
            : true,
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
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
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
  let availableFilterKeys = [
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
  if ((relationshipTypes ?? []).includes('targets')) {
    availableFilterKeys = [...availableFilterKeys, 'targets'];
  }
  return (
    <UserContext.Consumer>
      {({ platformModuleHelpers }) => (
        <>
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumnsEntities(platformModuleHelpers)}
              handleSort={storageHelpers.handleSort}
              handleSearch={storageHelpers.handleSearch}
              handleAddFilter={storageHelpers.handleAddFilter}
              handleRemoveFilter={storageHelpers.handleRemoveFilter}
              handleChangeView={storageHelpers.handleChangeView}
              onToggleEntity={onToggleEntity}
              handleToggleSelectAll={handleToggleSelectAll}
              paginationOptions={paginationOptions}
              selectAll={selectAll}
              keyword={searchTerm}
              displayImport={true}
              handleToggleExports={storageHelpers.handleToggleExports}
              openExports={openExports}
              exportEntityType={'Stix-Core-Object'}
              iconExtension={true}
              filters={filters}
              availableFilterKeys={availableFilterKeys}
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
            >
              <EntityStixCoreRelationshipsEntities
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={buildColumnsEntities(platformModuleHelpers)}
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
              filters={backgroundTaskFilters}
              search={searchTerm}
              handleClearSelectedElements={handleClearSelectedElements}
              variant="medium"
              warning={true}
              warningMessage={t(
                'Be careful, you are about to delete the selected entities (not the relationships!).',
              )}
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
              connectionKey={'Pagination_stixCoreObjects'}
              paddingRight={paddingRightButtonAdd ?? 220}
            />
          </Security>
        </>
      )}
    </UserContext.Consumer>
  );
};

export default EntityStixCoreRelationshipsEntitiesView;
