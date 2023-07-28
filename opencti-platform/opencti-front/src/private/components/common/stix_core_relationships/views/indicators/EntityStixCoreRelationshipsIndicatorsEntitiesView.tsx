import React, { FunctionComponent } from 'react';
import ListLines from '../../../../../../components/list_lines/ListLines';
import ToolBar from '../../../../data/ToolBar';
import useEntityToggle from '../../../../../../utils/hooks/useEntityToggle';
import { useFormatter } from '../../../../../../components/i18n';
import StixDomainObjectIndicatorsLines, { stixDomainObjectIndicatorsLinesQuery } from '../../../../observations/indicators/StixDomainObjectIndicatorsLines';
import Security from '../../../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity
  from '../../StixCoreRelationshipCreationFromEntity';
import { PaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { DataColumns, PaginationOptions } from '../../../../../../components/list_lines';
import {
  StixDomainObjectIndicatorsLinesQuery$data,
} from '../../../../observations/indicators/__generated__/StixDomainObjectIndicatorsLinesQuery.graphql';
import { cleanFilters, convertFilters } from '../../../../../../utils/ListParameters';
import { EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery$variables } from '../__generated__/EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery.graphql';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { QueryRenderer } from '../../../../../../relay/environment';

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
  const { t } = useFormatter();
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
    'labelledBy',
    'markedBy',
    'created_start_date',
    'created_end_date',
    'valid_from_start_date',
    'valid_until_end_date',
    'x_opencti_score',
    'createdBy',
    'objectContains',
    'sightedBy',
    'x_opencti_detection',
    'basedOn',
    'revoked',
    'creator',
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
      label: 'Creation date',
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

  const cleanedFilters = cleanFilters(filters, availableFilterKeys);

  const paginationFilters = convertFilters({
    ...cleanedFilters,
    indicates: [{ id: entityId, value: entityId }],
  });

  const paginationOptions = {
    search: searchTerm,
    orderBy: (sortBy && (sortBy in dataColumns) && dataColumns[sortBy].isSortable) ? sortBy : 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: paginationFilters,
  } as unknown as Partial<EntityStixCoreRelationshipsEntitiesViewLinesPaginationQuery$variables>; // Because of FilterMode

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
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={dataColumns}
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
            displayImport
            handleToggleExports={storageHelpers.handleToggleExports}
            openExports={openExports}
            exportEntityType={'Stix-Core-Object'}
            iconExtension
            filters={cleanedFilters}
            availableFilterKeys={availableFilterKeys}
            exportContext={`of-entity-${entityId}`}
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
            filters={cleanedFilters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="large"
            warning={true}
            warningMessage={t(
              'Be careful, you are about to delete the selected entities (not the relationships!).',
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
