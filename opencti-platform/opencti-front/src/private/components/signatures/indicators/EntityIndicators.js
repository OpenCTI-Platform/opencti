import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import EntityIndicatorsLines, {
  entityIndicatorsLinesQuery,
} from './EntityIndicatorsLines';

class EntityIndicators extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      lastSeenStart: null,
      lastSeenStop: null,
      targetEntityTypes: ['Indicator'],
      view: 'lines',
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: false,
      },
      valid_from: {
        label: 'Valid from',
        width: '15%',
        isSortable: false,
      },
      valid_until: {
        label: 'Valid until',
        width: '15%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      weight: {
        label: 'Confidence level',
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
        secondaryAction={true}
      >
        <QueryRenderer
          query={entityIndicatorsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityIndicatorsLines
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
    const { entityId, relationType } = this.props;
    const {
      view,
      targetEntityTypes,
      sortBy,
      orderAsc,
      lastSeenStart,
      lastSeenStop,
    } = this.state;
    const paginationOptions = {
      inferred: false,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationType,
      lastSeenStart: lastSeenStart || null,
      lastSeenStop: lastSeenStop || null,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
      </div>
    );
  }
}

EntityIndicators.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n)(EntityIndicators);
