import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, append, filter } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixObservablesLines, {
  stixObservablesLinesQuery,
} from './StixObservablesLines';
import inject18n from '../../../components/i18n';
import StixObservableCreation from './StixObservableCreation';
import StixObservablesRightBar from './StixObservablesRightBar';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
  header: {
    margin: '0 0 10px 0',
  },
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

class StixObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'created_at',
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      types: [],
      lastSeenStart: null,
      lastSeenStop: null,
    };
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggle(type) {
    if (this.state.types.includes(type)) {
      this.setState({ types: filter((t) => t !== type, this.state.types) });
    } else {
      this.setState({ types: append(type, this.state.types) });
    }
  }

  handleChangeLastSeenStart(lastSeenStart) {
    this.setState({ lastSeenStart });
  }

  handleChangeLastSeenStop(lastSeenStop) {
    this.setState({ lastSeenStop });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const displaySeen = !!(this.state.lastSeenStart || this.state.lastSeenStop);
    let dataColumns = {
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
        width: '10%',
        isSortable: true,
      },
    };
    if (displaySeen) {
      dataColumns = {
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
        first_seen: {
          label: 'First seen',
          width: '15%',
          isSortable: true,
        },
        last_seen: {
          label: 'Last seen',
          width: '15%',
          isSortable: true,
        },
        markingDefinitions: {
          label: 'Marking',
          width: '10%',
          isSortable: true,
        },
      };
    }
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
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
      view,
      types,
      sortBy,
      orderAsc,
      lastSeenStart,
      lastSeenStop,
      searchTerm,
    } = this.state;
    const paginationOptions = {
      types: this.state.types.length > 0 ? this.state.types : null,
      lastSeenStart,
      lastSeenStop,
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
          lastSeenStart={lastSeenStart}
          lastSeenStop={lastSeenStop}
          handleChangeLastSeenStart={this.handleChangeLastSeenStart.bind(this)}
          handleChangeLastSeenStop={this.handleChangeLastSeenStop.bind(this)}
        />
      </div>
    );
  }
}

StixObservables.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservables);
