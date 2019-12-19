import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, append, filter, propOr,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixObservablesLines, {
  stixObservablesLinesQuery,
} from './stix_observables/StixObservablesLines';
import inject18n from '../../../components/i18n';
import StixObservableCreation from './stix_observables/StixObservableCreation';
import StixObservablesRightBar from './stix_observables/StixObservablesRightBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class StixObservables extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'StixObservables-view',
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      types: [],
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'StixObservables-view',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState({ types: filter((t) => t !== type, this.state.types) });
    } else {
      this.setState({ types: append(type, this.state.types) });
    }
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '20%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '50%',
        isSortable: true,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      markingDefinitions: {
        label: 'Marking',
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
      >
        <QueryRenderer
          query={stixObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixObservablesLines
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
      view, types, sortBy, orderAsc, searchTerm,
    } = this.state;
    const paginationOptions = {
      types: this.state.types.length > 0 ? this.state.types : null,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixObservableCreation paginationOptions={paginationOptions} />
        <StixObservablesRightBar
          types={types}
          handleToggle={this.handleToggle.bind(this)}
        />
      </div>
    );
  }
}

StixObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixObservables);
