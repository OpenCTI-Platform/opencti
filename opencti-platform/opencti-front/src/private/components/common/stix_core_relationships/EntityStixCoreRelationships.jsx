import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import EntityStixCoreRelationshipsLinesFrom, {
  entityStixCoreRelationshipsLinesFromQuery,
} from './EntityStixCoreRelationshipsLinesFrom';
import EntityStixCoreRelationshipsLinesTo, {
  entityStixCoreRelationshipsLinesToQuery,
} from './EntityStixCoreRelationshipsLinesTo';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import EntityStixCoreRelationshipsLinesAll, {
  entityStixCoreRelationshipsLinesAllQuery,
} from './EntityStixCoreRelationshipsLinesAll';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ToolBar from '../../data/ToolBar';
import EntityStixCoreRelationshipsEntities from './EntityStixCoreRelationshipsEntities';
import ExportContextProvider from '../../../../utils/ExportContextProvider';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    display: 'flex',
  },
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

class EntityStixCoreRelationships extends Component {
  constructor(props) {
    super(props);
    let params = {};
    if (!props.noState) {
      params = buildViewParamsFromUrlAndStorage(
        props.history,
        props.location,
        `view-relationships-${props.entityId}-${props.stixCoreObjectTypes?.join(
          '-',
        )}-${props.relationshipTypes?.join('-')}`,
      );
    }
    this.state = {
      sortBy: R.propOr('created_at', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('entities', 'view', params),
      filters: R.propOr({}, 'filters', params),
      numberOfElements: { number: 0, symbol: '' },
      openExports: false,
    };
  }

  saveView() {
    if (!this.props.noState) {
      saveViewParameters(
        this.props.history,
        this.props.location,
        `view-relationships-${
          this.props.entityId
        }-${this.props.stixCoreObjectTypes?.join(
          '-',
        )}-${this.props.relationshipTypes?.join('-')}`,
        this.state,
      );
    }
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.saveView());
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
  }

  handleChangeView(mode) {
    this.setState({ view: mode, sortBy: 'created_at' }, () => this.saveView());
  }

  handleToggleSelectEntity(entity, event = null, forceRemove = []) {
    const { selectedElements, deSelectedElements, selectAll } = this.state;
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (Array.isArray(entity)) {
      const currentIds = R.values(selectedElements).map((n) => n.id);
      const givenIds = entity.map((n) => n.id);
      const addedIds = givenIds.filter((n) => !currentIds.includes(n));
      let newSelectedElements = {
        ...selectedElements,
        ...R.indexBy(
          R.prop('id'),
          entity.filter((n) => addedIds.includes(n.id)),
        ),
      };
      if (forceRemove.length > 0) {
        newSelectedElements = R.omit(
          forceRemove.map((n) => n.id),
          newSelectedElements,
        );
      }
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
        deSelectedElements: null,
      });
    } else if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else if (selectAll) {
      const newDeSelectedElements = R.assoc(
        entity.id,
        entity,
        deSelectedElements || {},
      );
      this.setState({
        deSelectedElements: newDeSelectedElements,
      });
    } else {
      const newSelectedElements = R.assoc(
        entity.id,
        entity,
        selectedElements || {},
      );
      this.setState({
        selectAll: false,
        selectedElements: newSelectedElements,
      });
    }
  }

  handleToggleSelectAll() {
    this.setState({
      selectAll: !this.state.selectAll,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  handleClearSelectedElements() {
    this.setState({
      selectAll: false,
      selectedElements: null,
      deSelectedElements: null,
    });
  }

  buildColumnRelationships(platformModuleHelpers) {
    const { stixCoreObjectTypes } = this.props;
    const isObservables = stixCoreObjectTypes?.includes(
      'Stix-Cyber-Observable',
    );
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
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
  }

  renderRelationships(paginationOptions, backgroundTaskFilters) {
    const {
      sortBy,
      orderAsc,
      numberOfElements,
      openExports,
      selectAll,
      selectedElements,
      deSelectedElements,
      filters,
      searchTerm,
      view,
    } = this.state;
    const {
      entityLink,
      entityId,
      isRelationReversed,
      allDirections,
      stixCoreObjectTypes,
      relationshipTypes,
      disableExport,
      enableNestedView,
      currentView,
      handleChangeView,
    } = this.props;
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    const finalView = currentView || view;
    return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={this.buildColumnRelationships(platformModuleHelpers)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              displayImport={true}
              secondaryAction={true}
              iconExtension={true}
              keyword={searchTerm}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
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
                disableExport ? null : this.handleToggleExports.bind(this)
              }
              openExports={openExports}
              exportEntityType="stix-core-relationship"
              noPadding={true}
              handleChangeView={
                handleChangeView
                  ? handleChangeView.bind(this)
                  : this.handleChangeView.bind(this)
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
                      dataColumns={this.buildColumnRelationships(
                        platformModuleHelpers,
                      )}
                      initialLoading={props === null}
                      setNumberOfElements={this.setNumberOfElements.bind(this)}
                      onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                      selectedElements={selectedElements}
                      deSelectedElements={deSelectedElements}
                      selectAll={selectAll}
                    />
                  ) : isRelationReversed ? (
                    <EntityStixCoreRelationshipsLinesTo
                      data={props}
                      paginationOptions={paginationOptions}
                      entityLink={entityLink}
                      dataColumns={this.buildColumnRelationships(
                        platformModuleHelpers,
                      )}
                      initialLoading={props === null}
                      setNumberOfElements={this.setNumberOfElements.bind(this)}
                      onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                      selectedElements={selectedElements}
                      deSelectedElements={deSelectedElements}
                      selectAll={selectAll}
                    />
                  ) : (
                    <EntityStixCoreRelationshipsLinesFrom
                      data={props}
                      paginationOptions={paginationOptions}
                      entityLink={entityLink}
                      dataColumns={this.buildColumnRelationships(
                        platformModuleHelpers,
                      )}
                      initialLoading={props === null}
                      setNumberOfElements={this.setNumberOfElements.bind(this)}
                      onToggleEntity={this.handleToggleSelectEntity.bind(this)}
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
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
                this,
              )}
              variant="medium"
            />
          </div>
        )}
      </UserContext.Consumer>
    );
  }

  buildColumnsEntities(platformModuleHelpers) {
    const { stixCoreObjectTypes } = this.props;
    const isObservables = stixCoreObjectTypes?.includes(
      'Stix-Cyber-Observable',
    );
    const isStixCoreObjects = !stixCoreObjectTypes || stixCoreObjectTypes.includes('Stix-Core-Object');
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
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
  }

  renderEntities(paginationOptions, backgroundTaskFilters) {
    const {
      sortBy,
      orderAsc,
      numberOfElements,
      openExports,
      selectAll,
      selectedElements,
      deSelectedElements,
      view,
      filters,
      searchTerm,
    } = this.state;
    const {
      entityLink,
      isRelationReversed,
      disableExport,
      stixCoreObjectTypes,
      relationshipTypes,
      handleChangeView,
      currentView,
      enableNestedView,
      t,
    } = this.props;
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
              dataColumns={this.buildColumnsEntities(platformModuleHelpers)}
              handleSort={this.handleSort.bind(this)}
              handleSearch={this.handleSearch.bind(this)}
              handleAddFilter={this.handleAddFilter.bind(this)}
              handleRemoveFilter={this.handleRemoveFilter.bind(this)}
              handleChangeView={
                handleChangeView
                  ? handleChangeView.bind(this)
                  : this.handleChangeView.bind(this)
              }
              onToggleEntity={this.handleToggleSelectEntity.bind(this)}
              handleToggleSelectAll={this.handleToggleSelectAll.bind(this)}
              paginationOptions={paginationOptions}
              selectAll={selectAll}
              keyword={searchTerm}
              displayImport={true}
              handleToggleExports={
                disableExport ? null : this.handleToggleExports.bind(this)
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
                    'Threat-Actor-Group',
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
                dataColumns={this.buildColumnsEntities(platformModuleHelpers)}
                onToggleEntity={this.handleToggleSelectEntity.bind(this)}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
                isRelationReversed={isRelationReversed}
                onLabelClick={this.handleAddFilter.bind(this)}
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
              handleClearSelectedElements={this.handleClearSelectedElements.bind(
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
  }

  render() {
    const {
      classes,
      stixCoreObjectTypes,
      entityId,
      role,
      relationshipTypes,
      isRelationReversed,
      allDirections,
      defaultStartTime,
      defaultStopTime,
      currentView,
      paddingRightButtonAdd,
    } = this.props;
    const { view, searchTerm, sortBy, orderAsc, filters } = this.state;
    const finalView = currentView || view;
    let selectedTypes;
    if (filters.entity_type && filters.entity_type.length > 0) {
      if (filters.entity_type.filter((o) => o.id === 'all').length > 0) {
        selectedTypes = [];
      } else {
        selectedTypes = filters.entity_type.map((o) => o.id);
      }
    } else {
      selectedTypes = Array.isArray(stixCoreObjectTypes) && stixCoreObjectTypes.length > 0
        ? stixCoreObjectTypes
        : [];
    }
    let selectedRelationshipTypes;
    if (filters.relationship_type && filters.relationship_type.length > 0) {
      if (filters.relationship_type.filter((o) => o.id === 'all').length > 0) {
        selectedRelationshipTypes = [];
      } else {
        selectedRelationshipTypes = filters.relationship_type.map((o) => o.id);
      }
    } else {
      selectedRelationshipTypes = Array.isArray(relationshipTypes) && relationshipTypes.length > 0
        ? relationshipTypes
        : [];
    }
    let backgroundTaskFilters = filters;
    const finalFilters = convertFilters(
      R.omit(['relationship_type', 'entity_type'], filters),
    );
    let paginationOptions;
    if (finalView === 'entities') {
      paginationOptions = {
        types: selectedTypes,
        relationship_type: selectedRelationshipTypes,
        elementId: entityId,
        search: searchTerm,
        orderBy: sortBy,
        orderMode: orderAsc ? 'asc' : 'desc',
        filters: finalFilters,
      };
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
    } else {
      paginationOptions = {
        relationship_type: selectedRelationshipTypes,
        search: searchTerm,
        orderBy: sortBy,
        orderMode: orderAsc ? 'asc' : 'desc',
        filters: finalFilters,
      };
      backgroundTaskFilters = {
        ...R.omit(['relationship_type', 'entity_type'], filters),
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
    }
    const finalStixCoreObjectTypes = stixCoreObjectTypes || [
      'Stix-Core-Object',
    ];
    const paddingRight = paddingRightButtonAdd ?? 220;
    const targetStixCyberObservableTypes = finalStixCoreObjectTypes.includes('Stix-Core-Object')
      || finalStixCoreObjectTypes.includes('Stix-Cyber-Observable')
      ? ['Stix-Cyber-Observable']
      : null;
    const stixCoreObjectTypesWithoutObservables = finalStixCoreObjectTypes.filter((n) => n !== 'Stix-Cyber-Observable');
    const targetStixDomainObjectTypes = stixCoreObjectTypesWithoutObservables.includes('Stix-Core-Object')
      ? ['Stix-Domain-Object']
      : stixCoreObjectTypesWithoutObservables;
    return (
      <ExportContextProvider>
        <div className={classes.container}>
          {finalView === 'relationships'
            && this.renderRelationships(paginationOptions, backgroundTaskFilters)}
          {finalView === 'entities'
            && this.renderEntities(paginationOptions, backgroundTaskFilters)}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipCreationFromEntity
              entityId={entityId}
              isRelationReversed={isRelationReversed}
              paddingRight={paddingRight}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              targetStixCyberObservableTypes={targetStixCyberObservableTypes}
              allowedRelationshipTypes={relationshipTypes}
              paginationOptions={paginationOptions}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              connectionKey={
                finalView === 'entities'
                  ? 'Pagination_stixCoreObjects'
                  : undefined
              }
            />
          </Security>
        </div>
      </ExportContextProvider>
    );
  }
}

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  noState: PropTypes.bool,
  disableExport: PropTypes.bool,
  handleChangeView: PropTypes.func,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
  paddingRightButtonAdd: PropTypes.string,
};

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(EntityStixCoreRelationships);
