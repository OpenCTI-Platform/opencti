import * as PropTypes from 'prop-types';
import React from 'react';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import ToolBar from '../../data/ToolBar';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectIndicatorsLines, { stixDomainObjectIndicatorsLinesQuery } from './StixDomainObjectIndicatorsLines';

const LOCAL_STORAGE_KEY = 'view-stixDomainObjectIndicatorsEntitiesView';
const StixDomainObjectIndicatorsEntitiesView = ({
  stixDomainObjectId,
  stixDomainObjectLink,
  localStorage,
  disableExport,
  handleChangeView,
  currentView,
  enableContextualView,
  indicatorTypes,
  observableTypes,
}) => {
  const { t } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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

  let finalFilters = filters;
  finalFilters = {
    ...finalFilters,
    indicates: [{ id: stixDomainObjectId, value: stixDomainObjectId }],
  };
  if (indicatorTypes.length) {
    finalFilters = {
      ...finalFilters,
      pattern_type: indicatorTypes.map((n) => ({ id: n, value: n })),
    };
  }
  if (observableTypes.length) {
    finalFilters = {
      ...finalFilters,
      x_opencti_main_observable_type: observableTypes.map((n) => ({
        id: n,
        value: n,
      })),
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
  const buildColumnsEntities = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
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
    numberOfSelectedElements = numberOfElements.original
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
        <div>
          <ListLines
            sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={buildColumnsEntities(platformModuleHelpers)}
            handleSort={storageHelpers.handleSort}
            handleSearch={storageHelpers.handleSearch}
            handleAddFilter={storageHelpers.handleAddFilter}
            handleRemoveFilter={storageHelpers.handleRemoveFilter}
            handleChangeView={handleChangeView ?? storageHelpers.handleChangeView}
            onToggleEntity={onToggleEntity}
            handleToggleSelectAll={handleToggleSelectAll}
            paginationOptions={paginationOptions}
            selectAll={selectAll}
            keyword={searchTerm}
            secondaryAction={true}
            displayImport={true}
            handleToggleExports={
              disableExport ? null : storageHelpers.handleToggleExports
            }
            openExports={openExports}//
            exportEntityType={'Stix-Core-Object'}//
            iconExtension={true}//
            filters={filters}//
            availableFilterKeys={availableFilterKeys}
            exportContext={`of-entity-${stixDomainObjectId}`}
            numberOfElements={numberOfElements}//
            noPadding={true}//
            enableContextualView={enableContextualView}
            currentView={finalView}
          >
            <QueryRenderer
              query={stixDomainObjectIndicatorsLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
                <StixDomainObjectIndicatorsLines
                  data={props}
                  paginationOptions={paginationOptions}
                  entityLink={stixDomainObjectLink}
                  entityId={stixDomainObjectId}
                  dataColumns={this.buildColumns(platformModuleHelpers)}
                  initialLoading={props === null}
                  setNumberOfElements={this.setNumberOfElements.bind(this)}
                  selectedElements={selectedElements}
                  deSelectedElements={deSelectedElements}
                  onToggleEntity={this.handleToggleSelectEntity.bind(this)}
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
            filters={finalFilters}
            search={searchTerm}
            handleClearSelectedElements={handleClearSelectedElements}
            variant="large"
            warning={true}
            warningMessage={t(
              'Be careful, you are about to delete the selected entities (not the relationships!).',
            )}
          />
        </div>
      )}
    </UserContext.Consumer>
  );
};

StixDomainObjectIndicatorsEntitiesView.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectLink: PropTypes.string,
  disableExport: PropTypes.bool,
  currentView: PropTypes.string,
  enableContextualView: PropTypes.bool,
  observableTypes: PropTypes.array,
  indicatorTypes: PropTypes.array,
  handleChangeView: PropTypes.func,
};
export default StixDomainObjectIndicatorsEntitiesView;
