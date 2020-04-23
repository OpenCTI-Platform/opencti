import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, assoc, compose, dissoc, filter, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import IndicatorsLines, {
  indicatorsLinesQuery,
} from './indicators/IndicatorsLines';
import IndicatorCreation from './indicators/IndicatorCreation';
import IndicatorsRightBar from './indicators/IndicatorsRightBar';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

const styles = () => ({
  container: {
    paddingRight: 250,
  },
});

class Indicators extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-indicators',
    );
    this.state = {
      sortBy: propOr('valid_from', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      indicatorTypes: propOr([], 'indicatorTypes', params),
      observableTypes: propOr([], 'observableTypes', params),
      filters: {},
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-indicators',
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
    this.setState({ openExports: !this.state.openExports });
  }

  handleToggleIndicatorType(type) {
    if (this.state.indicatorTypes.includes(type)) {
      this.setState(
        {
          indicatorTypes: filter((t) => t !== type, this.state.indicatorTypes),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          indicatorTypes: append(type, this.state.indicatorTypes),
        },
        () => this.saveView(),
      );
    }
  }

  handleToggleObservableType(type) {
    if (this.state.observableTypes.includes(type)) {
      this.setState(
        {
          observableTypes: filter(
            (t) => t !== type,
            this.state.observableTypes,
          ),
        },
        () => this.saveView(),
      );
    } else {
      this.setState(
        {
          observableTypes: append(type, this.state.observableTypes),
        },
        () => this.saveView(),
      );
    }
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
    const dataColumns = {
      pattern_type: {
        label: 'Pattern type',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      tags: {
        label: 'Tags',
        width: '20%',
        isSortable: false,
      },
      valid_from: {
        label: 'Valid from',
        width: '15%',
        isSortable: true,
      },
      valid_until: {
        label: 'Valid until',
        width: '15%',
        isSortable: true,
      },
      markingDefinitions: {
        label: 'Marking',
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
        exportEntityType="Indicator"
        exportContext={null}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'tags',
          'markingDefinitions',
          'created_start_date',
          'created_end_date',
          'valid_from_start_date',
          'valid_until_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={indicatorsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IndicatorsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              onTagClick={this.handleAddFilter.bind(this)}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const { classes } = this.props;
    const {
      view,
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      indicatorTypes,
      observableTypes,
      openExports,
    } = this.state;
    let finalFilters = convertFilters(filters);
    if (indicatorTypes.length > 0) {
      finalFilters = append(
        { key: 'pattern_type', values: indicatorTypes, operator: 'match' },
        finalFilters,
      );
    }
    if (observableTypes.length > 0) {
      finalFilters = append(
        {
          key: 'main_observable_type',
          values: observableTypes,
          operator: 'match',
        },
        finalFilters,
      );
    }
    const paginationOptions = {
      filters: finalFilters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IndicatorCreation
            paginationOptions={paginationOptions}
            openExports={openExports}
          />
        </Security>
        <IndicatorsRightBar
          indicatorTypes={indicatorTypes}
          observableTypes={observableTypes}
          handleToggleIndicatorType={this.handleToggleIndicatorType.bind(this)}
          handleToggleObservableType={this.handleToggleObservableType.bind(
            this,
          )}
          openExports={openExports}
        />
      </div>
    );
  }
}

Indicators.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Indicators);
