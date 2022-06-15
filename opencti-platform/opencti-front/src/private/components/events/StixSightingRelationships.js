import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import inject18n from '../../../components/i18n';
import StixSightingRelationshipsLines, {
  stixSightingRelationshipsLinesQuery,
} from './stix_sighting_relationships/StixSightingRelationshipsLines';
import { isUniqFilter } from '../common/lists/Filters';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';

class StixSightingRelationships extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-stix-sighting-relationships',
    );
    this.state = {
      sortBy: R.propOr('created', 'sortBy', params),
      orderAsc: R.propOr(false, 'orderAsc', params),
      searchTerm: R.propOr('', 'searchTerm', params),
      view: R.propOr('lines', 'view', params),
      filters: R.propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-stix-sighting-relationships',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports });
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

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = this.state;
    const dataColumns = {
      x_opencti_negative: {
        label: 'Eval',
        width: '10%',
        isSortable: true,
      },
      attribute_count: {
        label: 'Nb.',
        width: 80,
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '15%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '12%',
        isSortable: false,
      },
      entity: {
        label: 'Entity',
        width: '12%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '12%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '12%',
        isSortable: true,
      },
      confidence: {
        width: '10%',
        label: 'Confidence',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
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
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        exportEntityType="stix-sighting-relationship"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        secondaryAction={true}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'x_opencti_workflow_id',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'toSightingId',
        ]}
      >
        <QueryRenderer
          query={stixSightingRelationshipsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixSightingRelationshipsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onLabelClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { view, sortBy, orderAsc, searchTerm, filters } = this.state;
    let toSightingId = null;
    let processedFilters = filters;
    if (filters.toSightingId) {
      toSightingId = R.head(filters.toSightingId).id;
      processedFilters = R.dissoc('toSightingId', processedFilters);
    }
    const finalFilters = convertFilters(processedFilters);
    const paginationOptions = {
      fromRole: 'stix-sighting-relationship_from',
      toId: toSightingId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    return (
      <div>{view === 'lines' ? this.renderLines(paginationOptions) : ''}</div>
    );
  }
}

StixSightingRelationships.propTypes = {
  history: PropTypes.object,
  location: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(StixSightingRelationships);
