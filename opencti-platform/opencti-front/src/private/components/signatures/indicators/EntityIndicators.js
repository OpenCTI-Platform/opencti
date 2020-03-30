import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  append,
  assoc,
  dissoc,
  filter,
  head,
  last,
  map,
  pipe,
  propOr,
  toPairs,
} from 'ramda';
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
import IndicatorsRightBar from './IndicatorsRightBar';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

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
      view: propOr('lines', 'view', params),
      filters: {},
      indicatorTypes: [],
      observableTypes: [],
      openExports: false,
      inferred: false,
      numberOfElements: { number: 0, symbol: '' },
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

  handleAddFilter(key, id, value, event) {
    event.stopPropagation();
    event.preventDefault();
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
        noPadding={typeof this.props.onChangeOpenExports === 'function'}
        paginationOptions={exportPaginationOptions}
        exportEntityType="Indicator"
        exportContext={`of-entity-${entityId}`}
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
      inferred,
      searchTerm,
      filters,
      indicatorTypes,
      observableTypes,
      openExports,
    } = this.state;
    let finalFilters = pipe(
      toPairs,
      map((pair) => {
        const values = last(pair);
        const valIds = map((v) => v.id, values);
        return { key: head(pair), values: valIds };
      }),
    )(filters);
    if (indicatorTypes.length > 0) {
      finalFilters = append(
        { key: 'toPatternType', values: indicatorTypes },
        finalFilters,
      );
    }
    if (observableTypes.length > 0) {
      finalFilters = append(
        {
          key: 'toMainObservableType',
          operator: 'match',
          values: map(
            (type) => type.toLowerCase().replace('*', ''),
            observableTypes,
          ),
        },
        finalFilters,
      );
    }
    const paginationOptions = {
      inferred,
      search: searchTerm,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationType,
      lastSeenStart: null,
      lastSeenStop: null,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
      filters: finalFilters,
    };
    return (
      <div>
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixRelationCreationFromEntity
            entityId={entityId}
            isFrom={false}
            targetEntityTypes={['Indicator']}
            paginationOptions={paginationOptions}
            openExports={openExports}
            paddingRight={true}
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

EntityIndicators.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  history: PropTypes.object,
  onChangeOpenExports: PropTypes.func,
};

export default EntityIndicators;
