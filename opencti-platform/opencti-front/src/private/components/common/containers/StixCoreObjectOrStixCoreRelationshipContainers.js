import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, dissoc, propOr, uniqBy, prop,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import ListLines from '../../../../components/list_lines/ListLines';
import StixCoreObjectOrStixCoreRelationshipContainersLines, {
  stixCoreObjectOrStixCoreRelationshipContainersLinesQuery,
} from './StixCoreObjectOrStixCoreRelationshipContainersLines';
import inject18n from '../../../../components/i18n';

const VIEW_AS_KNOWLEDGE = 'knowledge';

class StixCoreObjectOrStixCoreRelationshipContainers extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-reports${
        props.stixCoreObjectOrStixCoreRelationshipId
          ? `-${props.stixCoreObjectOrStixCoreRelationshipId}`
          : ''
      }`,
    );
    this.state = {
      sortBy: propOr('created', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: propOr({}, 'filters', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
      viewAs: propOr(VIEW_AS_KNOWLEDGE, 'viewAs', params),
    };
  }

  componentDidUpdate(prevProps) {
    if (prevProps.viewAs !== this.props.viewAs) {
      this.setState({ viewAs: this.props.viewAs }, () => this.saveView());
    }
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-reports${
        this.props.stixCoreObjectOrStixCoreRelationshipId
          ? `-${this.props.stixCoreObjectOrStixCoreRelationshipId}`
          : ''
      }`,
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
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: assoc(
            key,
            uniqBy(prop('id'), [{ id, value }, ...this.state.filters[key]]),
            this.state.filters,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          filters: assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.saveView(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: dissoc(key, this.state.filters) }, () => this.saveView());
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
    const { stixCoreObjectOrStixCoreRelationshipId, authorId } = this.props;
    let exportContext = null;
    if (stixCoreObjectOrStixCoreRelationshipId) {
      exportContext = `of-entity-${stixCoreObjectOrStixCoreRelationshipId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }

    const dataColumns = {
      name: {
        label: 'Title',
        width: '30%',
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
        width: '15%',
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
        exportEntityType="Report"
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
          query={stixCoreObjectOrStixCoreRelationshipContainersLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixCoreObjectOrStixCoreRelationshipContainersLines
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
        params: { reportType },
      },
      stixCoreObjectOrStixCoreRelationshipId,
      authorId,
    } = this.props;
    const {
      view, sortBy, orderAsc, searchTerm, filters,
    } = this.state;
    const reportFilterClass = reportType !== 'all' && reportType !== undefined
      ? reportType.replace(/_/g, ' ')
      : '';
    const finalFilters = convertFilters(filters);
    if (reportFilterClass) {
      finalFilters.push({
        key: 'report_types',
        values: [reportFilterClass],
      });
    }
    if (authorId) finalFilters.push({ key: 'createdBy', values: [authorId] });
    if (stixCoreObjectOrStixCoreRelationshipId) {
      finalFilters.push({
        key: 'objectContains',
        values: [stixCoreObjectOrStixCoreRelationshipId],
      });
    }
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ marginTop: 20 }}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
      </div>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipContainers.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  authorId: PropTypes.string,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
  viewAs: PropTypes.string,
};

export default compose(
  inject18n,
  withRouter,
)(StixCoreObjectOrStixCoreRelationshipContainers);
