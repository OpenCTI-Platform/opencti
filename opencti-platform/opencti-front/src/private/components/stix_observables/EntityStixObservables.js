/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import EntityStixObservablesLines, {
  entityStixObservablesLinesQuery,
} from './EntityStixObservablesLines';
import StixObservablesRightBar from './StixObservablesRightBar';

const styles = () => ({
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

class EntityStixObservables extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: false,
      lastSeenStart: null,
      lastSeenStop: null,
      targetEntityTypes: [],
      toType: 'All',
      inferred: true,
      resolveInferences: false,
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleToggle(type) {
    if (this.state.targetEntityTypes.includes(type)) {
      this.setState({
        targetEntityTypes: filter(t => t !== type, this.state.targetEntityTypes),
      });
    } else {
      this.setState({
        targetEntityTypes: append(type, this.state.targetEntityTypes),
      });
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
    const { entityLink } = this.props;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      observable_value: {
        label: 'Value',
        width: '40%',
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
      weight: {
        label: 'Confidence level',
        width: '10%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        displayImport={false}
      >
        <QueryRenderer
          query={entityStixObservablesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityStixObservablesLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      entityId,
      relationType,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const {
      view,
      targetEntityTypes,
      sortBy,
      orderAsc,
      lastSeenStart,
      lastSeenStop,
      resolveInferences,
    } = this.state;
    const paginationOptions = {
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      inferred: this.state.inferred,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationType,
      lastSeenStart: lastSeenStart || null,
      lastSeenStop: lastSeenStop || null,
      orderBy: resolveInferences ? sortBy : null,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixObservablesRightBar
          types={targetEntityTypes}
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

EntityStixObservables.propTypes = {
  entityId: PropTypes.string,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  entityLink: PropTypes.string,
  relationType: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixObservables);
