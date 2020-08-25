import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, dissoc, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import OpinionsLines, { opinionsLinesQuery } from './opinions/OpinionsLines';
import inject18n from '../../../components/i18n';
import OpinionCreation from './opinions/OpinionCreation';

class Opinions extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-opinions${props.objectId ? `-${props.objectId}` : ''}`,
    );
    this.state = {
      sortBy: propOr('created', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: {},
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-opinions${this.props.objectId ? `-${this.props.objectId}` : ''}`,
      dissoc('filters', this.state),
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggleExports() {
    this.setState({ openExports: !this.state.openExports }, () => {
      if (typeof this.props.onChangeOpenExports === 'function') {
        this.props.onChangeOpenExports(this.state.openExports);
      }
    });
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    this.setState({
      filters: assoc(key, [{ id, value }], this.state.filters),
    });
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) });
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
    const { objectId, authorId } = this.props;
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }

    const dataColumns = {
      opinion: {
        label: 'Opinion',
        width: '40%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: false,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
        isSortable: false,
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
        noPadding={typeof this.props.onChangeOpenExports === 'function'}
        exportEntityType="Opinion"
        exportContext={exportContext}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'createdBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
        ]}
      >
        <QueryRenderer
          query={opinionsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <OpinionsLines
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
    const {
      match: {
        params: { opinionType },
      },
      objectId,
      authorId,
    } = this.props;
    const {
      view, sortBy, orderAsc, searchTerm, filters,
    } = this.state;
    const opinionFilterClass = opinionType !== 'all' && opinionType !== undefined
      ? opinionType.replace(/_/g, ' ')
      : '';
    const finalFilters = convertFilters(filters);
    if (opinionFilterClass) {
      finalFilters.push({
        key: 'opinion_types',
        values: [opinionFilterClass],
      });
    }
    if (authorId) finalFilters.push({ key: 'createdBy', values: [authorId] });
    if (objectId) finalFilters.push({ key: 'objectContains', values: [objectId] });
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <OpinionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

Opinions.propTypes = {
  objectId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
};

export default compose(inject18n, withRouter)(Opinions);
