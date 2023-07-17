import * as PropTypes from 'prop-types';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../relay/environment';
import EntityStixCoreRelationshipsLinesAll, {
  entityStixCoreRelationshipsLinesAllQuery,
} from './EntityStixCoreRelationshipsLinesAll';
import EntityStixCoreRelationshipsLinesTo, {
  entityStixCoreRelationshipsLinesToQuery,
} from './EntityStixCoreRelationshipsLinesTo';
import EntityStixCoreRelationshipsLinesFrom, {
  entityStixCoreRelationshipsLinesFromQuery,
} from './EntityStixCoreRelationshipsLinesFrom';
import ToolBar from '../../data/ToolBar';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';

const LOCAL_STORAGE_KEY = 'view-entityStixCoreRelationshipsRelationshipsView';
const EntityStixCoreRelationshipsRelationshipsView = ({
  backgroundTaskFilters,
  entityId,
  stixCoreObjectTypes,
  relationshipTypes,
  entityLink,
  isRelationReversed,
  allDirections,
  disableExport,
  handleChangeView,
  currentView,
  enableNestedView }) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {},
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
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
  const buildColumnRelationships = () => {
    const isObservables = stixCoreObjectTypes?.includes(
      'Stix-Cyber-Observable',
    );
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
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
    numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
  }
  const finalView = currentView;
  return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
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
              availableFilterKeys={[
                'relationship_type',
                'entity_type',
                'markedBy',
                'confidence',
                'createdBy',
                'creator',
                'created_start_date',
                'created_end_date',
              ]}
              availableEntityTypes={stixCoreObjectTypes}
              availableRelationshipTypes={relationshipTypes}
              handleToggleExports={
                disableExport ? null : storageHelpers.handleToggleExports
              }
              openExports={openExports}
              exportEntityType="stix-core-relationship"
              noPadding={true}
              handleChangeView={
                handleChangeView || handleChangeView
              }
              enableNestedView={enableNestedView}
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
                render={({ props }) =>
                  /* eslint-disable-next-line no-nested-ternary,implicit-arrow-linebreak */
                  (allDirections ? (
                    <EntityStixCoreRelationshipsLinesAll
                      data={props}
                      paginationOptions={paginationOptions}
                      entityLink={entityLink}
                      entityId={entityId}
                      dataColumns={buildColumnRelationships(
                        platformModuleHelpers,
                      )}
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
                      dataColumns={buildColumnRelationships(
                        platformModuleHelpers,
                      )}
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
                      dataColumns={buildColumnRelationships(
                        platformModuleHelpers,
                      )}
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
        )}
      </UserContext.Consumer>
  );
};

EntityStixCoreRelationshipsRelationshipsView.propTypes = {
  entityId: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  disableExport: PropTypes.bool,
  handleChangeView: PropTypes.func,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.func,
};
export default EntityStixCoreRelationshipsRelationshipsView;
