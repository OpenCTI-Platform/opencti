import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, append, filter, propOr, assoc, dissoc,
} from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixCyberObservablesLines, {
  stixCyberObservablesLinesQuery,
} from './stix_cyber_observables/StixCyberObservablesLines';
import inject18n from '../../../components/i18n';
import StixCyberObservableCreation from './stix_cyber_observables/StixCyberObservableCreation';
import StixCyberObservablesRightBar from './stix_cyber_observables/StixCyberObservablesRightBar';
import {
  buildViewParamsFromUrlAndStorage,
  convertFilters,
  saveViewParameters,
} from '../../../utils/ListParameters';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';

const styles = () => ({
  container: {
    paddingRight: 250,
  },
});

class StixCyberObservables extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-stix_cyber_observables',
    );
    this.state = {
      sortBy: propOr('created_at', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
      filters: {},
      observableTypes: propOr([], 'observableTypes', params),
      openExports: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-stix_cyber_observables',
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

  handleToggle(type) {
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
        { observableTypes: append(type, this.state.observableTypes) },
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
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '35%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Creation date',
        width: '18%',
        isSortable: true,
      },
      objectMarking: {
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
        exportEntityType="Stix-Cyber-Observable"
        exportContext={null}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_at_start_date',
          'created_at_end_date',
          'createdBy',
        ]}
      >
        <QueryRenderer
          query={stixCyberObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixCyberObservablesLines
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
    const { classes } = this.props;
    const {
      view,
      observableTypes,
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
    } = this.state;
    const finalFilters = convertFilters(filters);
    const paginationOptions = {
      types: observableTypes.length > 0 ? observableTypes : null,
      search: searchTerm,
      filters: finalFilters,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCyberObservableCreation
            paginationKey="Pagination_stixCyberObservables"
            paginationOptions={paginationOptions}
            openExports={openExports}
          />
        </Security>
        <StixCyberObservablesRightBar
          types={observableTypes}
          handleToggle={this.handleToggle.bind(this)}
          openExports={openExports}
        />
      </div>
    );
  }
}

StixCyberObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCyberObservables);
