import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
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
import { isUniqFilter } from '../lists/Filters';

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
        `view-relationships-${
          props.entityId
        }-${props.targetStixDomainObjectTypes?.join(
          '-',
        )}-${props.relationshipTypes?.join('-')}`,
      );
    }
    this.state = {
      sortBy: R.propOr('created', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      numberOfElements: { number: 0, symbol: '' },
      openEntityType: false,
      openRelationshipType: false,
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
        }-${this.props.targetStixDomainObjectTypes?.join(
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

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, numberOfElements, filters, openExports } = this.state;
    const {
      entityLink,
      entityId,
      isRelationReversed,
      allDirections,
      targetStixDomainObjectTypes,
      relationshipTypes,
      disableExport,
      handleChangeView,
      enableNestedView,
    } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '12%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      start_time: {
        label: 'Start time',
        width: '13%',
        isSortable: true,
      },
      stop_time: {
        label: 'Stop time',
        width: '13%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '13%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        handleAddFilter={this.handleAddFilter.bind(this)}
        handleRemoveFilter={this.handleRemoveFilter.bind(this)}
        displayImport={true}
        secondaryAction={true}
        numberOfElements={numberOfElements}
        filters={filters}
        availableFilterKeys={[
          'relationship_type',
          'entity_type',
          'markedBy',
          'createdBy',
          'created_start_date',
          'created_end_date',
        ]}
        availableEntityTypes={targetStixDomainObjectTypes}
        availableRelationshipTypes={relationshipTypes}
        handleToggleExports={
          disableExport ? null : this.handleToggleExports.bind(this)
        }
        openExports={openExports}
        exportEntityType="stix-core-relationship"
        noPadding={true}
        handleChangeView={handleChangeView}
        enableNestedView={enableNestedView}
        disableCards={true}
        paginationOptions={paginationOptions}
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
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ) : isRelationReversed ? (
              <EntityStixCoreRelationshipsLinesTo
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ) : (
              <EntityStixCoreRelationshipsLinesFrom
                data={props}
                paginationOptions={paginationOptions}
                entityLink={entityLink}
                dataColumns={dataColumns}
                initialLoading={props === null}
                setNumberOfElements={this.setNumberOfElements.bind(this)}
              />
            ))
          }
        />
      </ListLines>
    );
  }

  render() {
    const {
      classes,
      targetStixDomainObjectTypes,
      entityId,
      role,
      relationshipTypes,
      isRelationReversed,
      allDirections,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const { view, searchTerm, sortBy, orderAsc, filters } = this.state;
    let selectedTypes = [];
    if (filters.entity_type && filters.entity_type.length > 0) {
      if (R.filter((o) => o.id === 'all', filters.entity_type).length > 0) {
        selectedTypes = [];
      } else {
        selectedTypes = filters.entity_type.map((o) => o.id);
      }
    } else {
      selectedTypes = targetStixDomainObjectTypes;
    }
    let selectedRelationshipTypes = [];
    if (filters.relationship_type && filters.relationship_type.length > 0) {
      if (
        R.filter((o) => o.id === 'all', filters.relationship_type).length > 0
      ) {
        selectedRelationshipTypes = [];
      } else {
        selectedRelationshipTypes = filters.relationship_type.map((o) => o.id);
      }
    } else {
      selectedRelationshipTypes = Array.isArray(relationshipTypes) && relationshipTypes.length > 0
        ? relationshipTypes
        : [];
    }
    const finalFilters = convertFilters(
      R.pipe(R.dissoc('relationship_type'), R.dissoc('entity_type'))(filters),
    );
    let paginationOptions = {
      relationship_type: selectedRelationshipTypes,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    if (allDirections) {
      paginationOptions = R.pipe(
        R.assoc('elementId', entityId),
        R.assoc('elementWithTargetTypes', selectedTypes),
      )(paginationOptions);
    } else if (isRelationReversed) {
      paginationOptions = R.pipe(
        R.assoc('fromTypes', selectedTypes),
        R.assoc('toId', entityId),
        R.assoc('toRole', role || null),
      )(paginationOptions);
    } else {
      paginationOptions = R.pipe(
        R.assoc('fromId', entityId),
        R.assoc('fromRole', role || null),
        R.assoc('toTypes', selectedTypes),
      )(paginationOptions);
    }
    return (
      <div className={classes.container}>
        {view === 'lines' && this.renderLines(paginationOptions)}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            entityId={entityId}
            isRelationReversed={isRelationReversed}
            paddingRight={220}
            targetStixDomainObjectTypes={targetStixDomainObjectTypes}
            allowedRelationshipTypes={relationshipTypes}
            paginationOptions={paginationOptions}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
          />
        </Security>
      </div>
    );
  }
}

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  targetStixDomainObjectTypes: PropTypes.array,
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
  enableNestedView: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(EntityStixCoreRelationships);
