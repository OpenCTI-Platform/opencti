import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { propOr } from 'ramda';
import EntityIndicatorsLines, {
  entityIndicatorsLinesQuery,
} from './EntityIndicatorsLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { QueryRenderer } from '../../../../relay/environment';
import StixRelationCreationFromEntity from '../../common/stix_relations/StixRelationCreationFromEntity';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';

class EntityIndicators extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-indicators-${props.entityId}`,
    );
    this.state = {
      sortBy: propOr('first_seen', 'sortBy', params),
      orderAsc: propOr(false, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: 'lines',
      lastSeenStart: null,
      lastSeenStop: null,
      targetEntityTypes: ['Indicator'],
      inferred: false,
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-indicators-${this.props.entityId}`,
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

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  renderLines(paginationOptions) {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      openExports,
      numberOfElements,
    } = this.state;
    const { entityId, entityLink } = this.props;
    const dataColumns = {
      toPatternType: {
        label: 'Type',
        width: '10%',
        isSortable: true,
      },
      toName: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      tags: {
        label: 'Tags',
        width: '15%',
        isSortable: false,
      },
      toValidFrom: {
        label: 'Valid from',
        width: '15%',
        isSortable: true,
      },
      toValidUntil: {
        label: 'Valid until',
        width: '15%',
        isSortable: true,
      },
      markingDefinitions: {
        label: 'Marking',
        isSortable: false,
      },
    };
    const orderByMapping = {
      toPatternType: 'pattern_type',
      toName: 'name',
      toValidFrom: 'valid_from',
      toValidUntil: 'valid_until',
    };
    const exportPaginationOptions = {
      filters: [{ key: 'indicates', values: [entityId] }],
      orderBy: orderByMapping[sortBy === 'first_seen' ? 'toValidFrom' : sortBy],
      orderMode: orderAsc ? 'asc' : 'desc',
      search: searchTerm,
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
        paginationOptions={exportPaginationOptions}
        exportEntityType="Indicator"
        keyword={searchTerm}
        secondaryAction={true}
        numberOfElements={numberOfElements}
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
              setNumberOfElements={this.setNumberOfElements.bind(this)}
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
      inferred,
      searchTerm,
    } = this.state;
    const paginationOptions = {
      inferred,
      search: searchTerm,
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
        <StixRelationCreationFromEntity
          entityId={entityId}
          isFrom={false}
          targetEntityTypes={['Indicator']}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

EntityIndicators.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  history: PropTypes.object,
};

export default EntityIndicators;
