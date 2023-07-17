import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { withRouter } from 'react-router-dom';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ToolBar from '../../data/ToolBar';
import EntityStixCoreRelationshipsEntities from './EntityStixCoreRelationshipsEntities';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './EntityStixCoreRelationshipsEntitiesView';

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
            && <EntityStixCoreRelationshipsRelationshipsView
            entityId={entityId}
            backgroundTaskFilters={backgroundTaskFilters}
            stixCoreObjectTypes={stixCoreObjectTypes}
            relationshipTypes={relationshipTypes}
            entityLink={entityLink}
            isRelationReversed={isRelationReversed}
            allDirections={allDirections}
            disableExport={disableExport}
            handleChangeView={handleChangeView}
            currentView={currentView}
            enableNestedView={enableNestedView}
            />}
          {finalView === 'entities'
            && <EntityStixCoreRelationshipsEntitiesView
              backgroundTaskFilters={backgroundTaskFilters}
              stixCoreObjectTypes={stixCoreObjectTypes}
              relationshipTypes={relationshipTypes}
              entityLink={entityLink}
              isRelationReversed={isRelationReversed}
              disableExport={disableExport}
              handleChangeView={handleChangeView}
              currentView={currentView}
              enableNestedView={enableNestedView}
            />}
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
