import React, { FunctionComponent } from 'react';
import * as PropTypes from 'prop-types';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import ToolBar from '../../data/ToolBar';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectIndicatorsLines, { stixDomainObjectIndicatorsLinesQuery } from '../../observations/indicators/StixDomainObjectIndicatorsLines';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity
  from './StixCoreRelationshipCreationFromEntity';
import { PaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../components/list_lines';
import {
  StixDomainObjectIndicatorsLinesQuery$data,
} from '../../observations/indicators/__generated__/StixDomainObjectIndicatorsLinesQuery.graphql';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';

const LOCAL_STORAGE_KEY = 'view-stixDomainObjectIndicatorsEntitiesView';

interface EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesViewProps {
  entityId: string
  entityLink: string
  localStorage: PaginationLocalStorage<PaginationOptions>
  currentView: string
  defaultStartTime: string
  defaultStopTime: string
  enableContextualView: boolean,
}
const EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesView: FunctionComponent<EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesViewProps> = ({
  entityId,
  entityLink,
  localStorage,
  currentView,
  defaultStartTime,
  defaultStopTime,
  enableContextualView,
}) => {
  const { t } = useFormatter();
  const { viewStorage, helpers: storageHelpers, paginationOptions } = localStorage;
  const {
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    view,
    numberOfElements,
    openExports,
  } = viewStorage;

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(LOCAL_STORAGE_KEY);
  const buildColumnsEntities = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable() ?? false;
    return {
      pattern_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '30%',
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
      },
    };
  };

  let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
  if (selectAll) {
    numberOfSelectedElements = (numberOfElements?.original ?? 0)
      - Object.keys(deSelectedElements || {}).length;
  }
  const finalView = currentView || view;
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
            secondaryAction={true}
            displayImport={true}
            handleToggleExports={storageHelpers.handleToggleExports}
            openExports={openExports}
            exportEntityType={'Stix-Core-Object'}
            iconExtension={true}
            filters={filters}
            availableFilterKeys={availableFilterKeys}
            exportContext={`of-entity-${entityId}`}
            numberOfElements={numberOfElements}
            noPadding={true}
            currentView={finalView}
          >
            <QueryRenderer
              query={stixDomainObjectIndicatorsLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({
                props,
              }: {
                props: StixDomainObjectIndicatorsLinesQuery$data;
              }) => (
                <StixDomainObjectIndicatorsLines
                  data={props}
                  paginationOptions={paginationOptions}
                  entityLink={entityLink}
                  entityId={entityId}
                  dataColumns={buildColumnsEntities(platformModuleHelpers)}
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
            filters={filters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="large"
            warning={true}
            warningMessage={t(
              'Be careful, you are about to delete the selected entities (not the relationships!).',
            )}
          />
        </div>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          isRelationReversed={true}
          targetStixDomainObjectTypes={['Indicator']}
          paginationOptions={paginationOptions}
          openExports={openExports}
          paddingRight={270}
          connectionKey="Pagination_indicators"
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
          />
          </Security>
        </>
      )}
    </UserContext.Consumer>
  );
};
export default EntityStixCoreRelationshipsForStixDomainObjectIdIndicatorsEntitiesView;
