import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append, compose, filter, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import IndicatorsLines, {
  indicatorsLinesQuery,
} from './indicators/IndicatorsLines';
import IndicatorCreation from './indicators/IndicatorCreation';
import IndicatorsRightBar from './indicators/IndicatorsRightBar';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class Indicators extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'Indicators-view',
    );
    this.state = {
      sortBy: propOr('valid_from', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      indicatorTypes: [],
      observableTypes: [],
      openExports: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'Indicators-view',
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

  handleToggleIndicatorType(type) {
    if (this.state.indicatorTypes.includes(type)) {
      this.setState({
        indicatorTypes: filter((t) => t !== type, this.state.indicatorTypes),
      });
    } else {
      this.setState({
        indicatorTypes: append(type, this.state.indicatorTypes),
      });
    }
  }

  handleToggleObservableType(type) {
    if (this.state.observableTypes.includes(type)) {
      this.setState({
        observableTypes: filter((t) => t !== type, this.state.observableTypes),
      });
    } else {
      this.setState({
        observableTypes: append(type, this.state.observableTypes),
      });
    }
  }

  renderLines(paginationOptions) {
    const {
      sortBy, orderAsc, searchTerm, openExports,
    } = this.state;
    const dataColumns = {
      pattern_type: {
        label: 'Pattern type',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
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
        handleToggleExports={this.handleToggleExports.bind(this)}
        openExports={openExports}
        exportEntityType="Indicator"
        keyword={searchTerm}
        paginationOptions={paginationOptions}
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
      indicatorTypes,
      observableTypes,
      openExports,
    } = this.state;
    let filters = [];
    if (indicatorTypes.length > 0) {
      filters = append(
        { key: 'pattern_type', values: indicatorTypes, operator: 'match' },
        filters,
      );
    }
    if (observableTypes.length > 0) {
      filters = append(
        {
          key: 'main_observable_type',
          values: observableTypes,
          operator: 'match',
        },
        filters,
      );
    }
    const paginationOptions = {
      filters,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <IndicatorCreation
          paginationOptions={paginationOptions}
          openExports={openExports}
        />
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
