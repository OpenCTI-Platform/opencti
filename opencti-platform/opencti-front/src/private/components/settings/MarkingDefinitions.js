import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import MarkingDefinitionsLines, {
  markingDefinitionsLinesQuery,
} from './marking_definitions/MarkingDefinitionsLines';
import MarkingDefinitionCreation from './marking_definitions/MarkingDefinitionCreation';
import AccessesMenu from './AccessesMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class MarkingDefinitions extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'MarkingDefinitions-view',
    );
    this.state = {
      sortBy: propOr('definition', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'MarkingDefinitions-view',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      definition_type: {
        label: 'Type',
        width: '25%',
        isSortable: true,
      },
      definition: {
        label: 'Definition',
        width: '25%',
        isSortable: true,
      },
      x_opencti_color: {
        label: 'Color',
        width: '15%',
        isSortable: true,
      },
      x_opencti_order: {
        label: 'Order',
        width: '10%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '15%',
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
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={markingDefinitionsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <MarkingDefinitionsLines
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
    const { view, sortBy, orderAsc, searchTerm } = this.state;
    const paginationOptions = {
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <AccessesMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <MarkingDefinitionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

MarkingDefinitions.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(MarkingDefinitions);
