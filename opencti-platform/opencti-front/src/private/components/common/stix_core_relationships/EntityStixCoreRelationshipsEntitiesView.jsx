import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import ToolBar from '../../data/ToolBar';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import EntityStixCoreRelationshipsEntities from './EntityStixCoreRelationshipsEntities';
import { useFormatter } from '../../../../components/i18n';
import { convertFilters } from '../../../../utils/ListParameters';

const LOCAL_STORAGE_KEY = 'view-entityStixCoreRelationshipsEntitiesView';
const EntityStixCoreRelationshipsEntitiesView = ({
  localStorage,
  entityId,
  stixCoreObjectTypes,
  relationshipTypes,
  entityLink,
  isRelationReversed,
  disableExport,
  currentView,
  enableNestedView }) => {
  const { t } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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

  const paginationOptions = { // Rework pagination options for Query
    types: selectedTypes,
    relationship_type: selectedRelationshipTypes,
    elementId: entityId,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: convertFilters(
      R.omit(['relationship_type', 'entity_type'], filters),
    ),
  };

  let backgroundTaskFilters;
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
  const buildColumnsEntities = () => {
    const isObservables = stixCoreObjectTypes?.includes(
      'Stix-Cyber-Observable',
    );
    const isStixCoreObjects = !stixCoreObjectTypes || stixCoreObjectTypes.includes('Stix-Core-Object');
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
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
        isSortable: isStixCoreObjects
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
    numberOfSelectedElements = numberOfElements.original
      - Object.keys(deSelectedElements || {}).length;
  }
  const finalView = currentView || view;
  let availableFilterKeys = [
    'relationship_type',
    'entity_type',
    'markedBy',
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
            handleToggleExports={
              disableExport ? null : storageHelpers.handleToggleExports
            }
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
            handleClearSelectedElements={handleClearSelectedElements.bind(
              this,
            )}
            variant="medium"
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

EntityStixCoreRelationshipsEntitiesView.propTypes = {
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  disableExport: PropTypes.bool,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.func,
};
export default EntityStixCoreRelationshipsEntitiesView;
